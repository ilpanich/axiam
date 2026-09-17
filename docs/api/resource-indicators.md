# Resource Indicators (RFC 8707)

By default an AXIAM access token is addressed at AXIAM: its `aud` claim is
`axiam:user` for a token that represents a person and `axiam:m2m` for one that
represents a machine. That is the right answer when the token is going to be
presented back to AXIAM, and the wrong answer the moment it is going to be
presented to something else — an MCP server, a partner API, one service in a
mesh.

RFC 8707 is the parameter that says where a token is going. A client sends
`resource=<absolute URI>` and the token it receives carries that URI as its
`aud`, so the resource server can check that the token in its hand was minted
for **it** and not for a neighbour.

Everything on this page is opt-in. A request that sends no `resource` gets
exactly the token it has always got.

## Registering what a client may address

A client may only name resources its registration lists in
`allowed_resources`. That field is the single source of truth for this, and it
is empty on every client that existed before resource indicators did — so such
a client may name nothing, and asking gets `invalid_target`.

```bash
curl -X POST https://id.example.com/api/v1/oauth2-clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
        "name": "Claude Code",
        "redirect_uris": ["http://127.0.0.1/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "token_endpoint_auth_method": "none",
        "allowed_resources": ["https://mcp.example.com/mcp"]
      }'
```

`allowed_resources` is a whole-list field on `PATCH` as well: sending it
replaces the list, and `[]` withdraws every target.

### What an entry must be

Each entry is an **absolute URI without a fragment**, which is RFC 8707 §2's
rule verbatim. A relative reference, or one carrying a `#fragment`, is refused
at registration with a `400` naming the offending entry rather than being
stored and refused later at a client nobody is watching. A query is permitted:
the RFC only discourages one.

### How entries are compared

Entries are stored, returned and compared in their **RFC 3986 §6.2.2
normalised** form, so `HTTPS://MCP.Example.COM:443/mcp` and
`https://mcp.example.com/mcp` are one resource and not two. Reading the
registration back shows the normalised string, which is the string the request
path will compare.

Comparison is **never by prefix**. `https://mcp.example.com` does not authorise
`https://mcp.example.com.attacker.test`, or `https://mcp.example.com/anything`
— register each resource you mean. A prefix rule here would be the audience
equivalent of the open redirect that exact `redirect_uri` matching exists to
prevent.

Normalisation stops where RFC 3986's *syntax-based* rules stop. The scheme and
host are lowercased, a default port is dropped and dot segments are removed.
The path's case is **not** folded, a trailing slash is **not** forgiven, and a
percent-encoded unreserved character in the path is **not** decoded — so
`/mcp`, `/MCP`, `/mcp/` and `/%6Dcp` are four resources. Every one of those is a
refusal rather than an admission, which is the direction to err in; register
the exact form your resource server publishes.

## Asking for a resource

### Authorization code grant

`resource` goes on the authorization request, beside the other parameters:

```bash
curl -G https://id.example.com/oauth2/authorize \
  --data-urlencode 'response_type=code' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode 'redirect_uri=http://127.0.0.1:53127/callback' \
  --data-urlencode 'scope=openid profile' \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode 'code_challenge_method=S256' \
  --data-urlencode 'resource=https://mcp.example.com/mcp'
```

The value is validated there, against `allowed_resources`, and recorded on the
authorization code. The token request may repeat it or leave it out; either
way the access token comes back addressed at the resource:

```bash
curl -X POST "https://id.example.com/oauth2/token?tenant_id=$TENANT" \
  -d grant_type=authorization_code \
  -d "code=$CODE" \
  -d 'redirect_uri=http://127.0.0.1:53127/callback' \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$VERIFIER" \
  -d 'resource=https://mcp.example.com/mcp'
```

```json
{ "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 900 }
```

whose claims carry `"aud": "https://mcp.example.com/mcp"`.

### Pushed authorization requests

`resource` is a pushed parameter like any other, and is validated at
`/oauth2/par` — where the client is authenticated, so a refusal is
attributable and reaches the client as a protocol error instead of surfacing in
a browser after a sign-in the user should never have been asked for.

```bash
curl -X POST "https://id.example.com/oauth2/par?tenant_id=$TENANT" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d response_type=code \
  -d 'redirect_uri=https://rp.example.com/callback' \
  -d 'scope=openid' \
  -d "code_challenge=$CHALLENGE" -d code_challenge_method=S256 \
  -d 'resource=https://mcp.example.com/mcp'
```

The pushed copy wins: a `resource` added to the query string beside the
`request_uri` is ignored, exactly as `state`, `nonce` and `dpop_jkt` are. A
browser cannot re-address a request its client pushed.

### Device authorization grant

The device names its target when it starts the flow, because the poll that
redeems the grant carries nothing but a `device_code`:

```bash
curl -X POST "https://id.example.com/oauth2/device_authorization?tenant_id=$TENANT" \
  -d "client_id=$CLIENT_ID" \
  -d 'scope=openid' \
  -d 'resource=https://mcp.example.com/mcp'
```

A poll may repeat the value or omit it.

### Client credentials

The machine grant has no earlier credential to inherit a target from, so it is
the one grant where `resource` is checked against `allowed_resources` at the
token endpoint itself:

```bash
curl -X POST "https://id.example.com/oauth2/token?tenant_id=$TENANT" \
  -d grant_type=client_credentials \
  -d "client_id=$CLIENT_ID" -d "client_secret=$CLIENT_SECRET" \
  -d 'scope=read' \
  -d 'resource=https://mcp.example.com/mcp'
```

Without the parameter this grant mints `axiam:m2m`, as it always has.

### Token exchange

The RFC 8693 grant has honoured `resource` (and its synonym `audience`) since
it shipped. It now reads `allowed_resources` too — see
[`token-exchange.md#audience`](token-exchange.md#audience), which also
documents the deprecated rule it replaces.

## A grant's audience is decided when the grant is made

This is the rule everything above rests on, and it has one consequence worth
stating on its own: **a token cannot be widened by refreshing it.**

The resource travels with the grant — onto the authorization code, onto the
device grant, and onto the refresh token, where each rotation copies it
forward. At redemption and at refresh the only thing a client may do with the
parameter is repeat it:

| The grant is bound to | The request names | Answer |
| --- | --- | --- |
| `https://mcp.example.com/mcp` | nothing | the token is minted for `https://mcp.example.com/mcp` |
| `https://mcp.example.com/mcp` | the same URI | the same |
| `https://mcp.example.com/mcp` | a different URI | `invalid_target` |
| nothing | a URI | `invalid_target` |
| nothing | nothing | `axiam:user` / `axiam:m2m`, as always |

The last two rows are the ones that matter. A refresh token issued for
`axiam:user` represents a consent the end user gave to a client acting as them
*at AXIAM*; letting a refresh add `resource=https://mcp.example.com` would mint
a token for a service the end user was never asked about, fifteen minutes after
they stopped watching. The same reasoning refuses it at code redemption.

Note that this rule does **not** consult `allowed_resources`. That list was
consulted when the grant was made; a registration edited since must not be able
to change what an outstanding grant means.

## `invalid_target`

Every refusal on this page is RFC 8707 §2's `invalid_target` — the target is
well-formed, it is simply not one this server will issue this client a token
for. At the authorization endpoint it is delivered by redirecting to the
client's registered `redirect_uri` (the client and the URI have both been
validated by the time it is decided); everywhere else it is the ordinary JSON
error body:

```json
{
  "error": "invalid_target",
  "error_description": "the requested resource is not one this client may address; register it in allowed_resources first"
}
```

A malformed `resource` and an unregistered one are both `invalid_target`, with
different descriptions. RFC 8707 defines no separate code for "that is not a
URI", and inventing one would make the two distinguishable to a caller probing
which resources a client may address.

### One resource per request

RFC 8707 permits the parameter to repeat. AXIAM accepts **one** value and
answers `invalid_target` to a second, because an AXIAM access token carries a
single `aud` string and there is no honest way to serve two targets with one
token. Start a separate authorization for each resource.

## What a resource-bound token is not

**It is not a token for AXIAM.** This is the whole safety argument for the
feature, so it is worth being blunt about: a token minted for
`https://mcp.example.com/mcp` is rejected with `401` by AXIAM's own REST
endpoints and with `UNAUTHENTICATED` by its gRPC surface. AXIAM's extractors
accept `axiam:user` and `axiam:m2m` and nothing else, and that did not change
when this feature arrived.

So a client that asks for a token for somebody else gets a token it cannot turn
around and use here. If your client needs both — to call AXIAM's API *and* an
MCP server — it needs two tokens, from two authorizations.

The mirror of that rule is introspection. `POST /oauth2/introspect` will
happily describe a resource-bound token, including its `aud` (RFC 7662 §2.2),
because an introspecting resource server's whole audience check is "is this
token for me" and it has no other way to ask:

```json
{
  "active": true,
  "sub": "…",
  "aud": "https://mcp.example.com/mcp",
  "scope": "openid profile",
  "exp": 1789000000,
  "token_type": "Bearer"
}
```

Revocation (`POST /oauth2/revoke`) works on a resource-bound grant's refresh
token exactly as on any other.

## Sender constraining is orthogonal

RFC 9449 (DPoP) and RFC 8705 (mTLS) bind a token to a **key**; RFC 8707 binds
it to a **resource**. They answer different questions and compose freely: a
token can carry both a `cnf` confirmation and a third-party `aud`, and the
resource server must then satisfy both. For a token that leaves AXIAM's own
estate that is the recommended posture — register the client with
`dpop_bound_access_tokens: true` alongside its `allowed_resources`.

## See also

- [`token-exchange.md`](token-exchange.md) — the RFC 8693 grant's own
  `audience`/`resource` rules and the deprecated redirect-URI branch.
- [`../admin/public-clients.md`](../admin/public-clients.md) — registering the
  desktop clients that most often want a resource-bound token.
