# Identity for agents

An AI agent, an MCP client, an automation that acts for a person: each is a
non-human caller that sometimes needs an identity of its own and sometimes
needs to speak for a user. AXIAM does not have a separate "agent account" type,
and does not need one. What it has is the set of standard pieces below, and
this guide walks one agent through them end to end.

| An agent needs to… | AXIAM piece | Standard |
| --- | --- | --- |
| Exist as a machine identity | [Service account](#1-register-the-agent) or confidential OAuth2 client | RFC 6749 client credentials, RFC 8705 mTLS |
| Arrive without an administrator registering it | Dynamic client registration, or a Client ID Metadata Document | RFC 7591, `draft-ietf-oauth-client-id-metadata-document` |
| Run on a user's machine | Public client with a loopback redirect | RFC 8252 §7.3, PKCE |
| Act on behalf of a user, visibly | Token exchange with an `act` claim | RFC 8693 |
| Receive a token addressed at one server | Resource indicators | RFC 8707 |
| Be a protected server an agent calls | The SDK's MCP resource-server helpers | RFC 9728, RFC 6750 |
| Be cut off | Revocation endpoint, session revocation feed, short lifetimes | RFC 7009 |

Everything here is shipped. Nothing here is a new protocol: the value is in
knowing which piece answers which question, and which combinations the server
refuses.

This page links out for every field and every error. It does not restate the
pages it points at; where it says something normative, the linked page is the
authority. The SDK operation names are those of
[`sdks/CONTRACT.md`](../../sdks/CONTRACT.md) §15 (token exchange) and §28
(MCP resource-server helpers), in the casing each language's contract table
gives.

## Contents

1. [Register the agent](#1-register-the-agent)
2. [Act on behalf of a user](#2-act-on-behalf-of-a-user)
3. [Address the token at one server](#3-address-the-token-at-one-server)
4. [Be the server an agent calls](#4-be-the-server-an-agent-calls)
5. [Revoke](#5-revoke)
6. [What AXIAM does not do](#6-what-axiam-does-not-do)

---

## 1. Register the agent

The first decision is **what kind of caller the agent is**, because the
registration paths are not interchangeable. The grants a client may hold depend
on how it was registered, and the server refuses the combinations that would let
a stranger mint a token on the strength of an identity nobody vetted.

| The agent is… | Register it as | May hold |
| --- | --- | --- |
| A backend you operate, acting as itself | A **service account** (`sa_…` client id), with a secret or a bound X.509 certificate | `client_credentials` |
| A backend you operate, acting for users | A **confidential OAuth2 client** (`oa_…`), created by an administrator | `authorization_code`, `refresh_token`, `client_credentials` and, when you register it for it, `urn:ietf:params:oauth:grant-type:token-exchange` |
| A desktop or CLI agent on the user's machine (Claude Code, VS Code, MCP Inspector) | A **public client** with a loopback redirect, or a CIMD / dynamically registered client | `authorization_code` with PKCE, `refresh_token` |
| An agent nobody registered in advance | **Dynamic client registration** or a **Client ID Metadata Document** | `authorization_code`, `refresh_token` only |

Three consequences of the table are worth reading twice, because each is a
refusal you will otherwise meet at runtime:

- **A public client cannot use `client_credentials` or token exchange.** It
  presents no credential, so neither operation would be attributable.
  Registration refuses the grant and the token endpoint refuses it again at
  request time.
- **A dynamically registered or CIMD client can never hold either grant.** Both
  mechanisms hand a `client_id` to a party AXIAM did not vet; their grant lists
  are limited to `authorization_code` and `refresh_token`. They also cannot name
  their own audiences: those come from the tenant's
  `external_client_allowed_resources`, and consent is forced on for the first
  authorization per user.
- **A service account is not an OAuth2 client.** It has no registered scopes, so
  its token carries no `scope` claim and its authorization comes from the roles
  assigned to it. Its `sub` is its UUID with `sub_kind: service_account`, and
  its token is addressed at `axiam:m2m`.

### A machine identity: the service account

```bash
curl -X POST https://id.example.com/api/v1/service-accounts \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name": "orders-agent", "description": "Reconciles orders overnight"}'
```

The secret is returned once. Rotate it with
`POST /api/v1/service-accounts/{sa_id}/rotate-secret`; there is no recovery.
Where a secret is the wrong credential, bind an X.509 certificate with
`POST /api/v1/service-accounts/{sa_id}/bind-certificate` and authenticate by
mutual TLS instead, so the credential is a key that never leaves the machine
([PKI](../pki/README.md)). Give the account roles as you would a user; it is
authorized by the same engine, and an explicit deny overrides every allow.

The agent obtains a token with the client-credentials grant (the
`login_client_credentials` operation in every SDK; the request is the same for a
service account and for an OAuth2 client):

```bash
curl -X POST "https://id.example.com/oauth2/token?tenant_id=$TENANT_ID" \
  -d grant_type=client_credentials \
  -d client_id="$SA_CLIENT_ID" -d client_secret="$SA_CLIENT_SECRET"
```

A resource server that accepts machine callers must expect `aud: axiam:m2m`;
a guard configured for `axiam:user` rejects the token, correctly
([CONTRACT §12.1](../../sdks/CONTRACT.md)).

### A local agent: public client, loopback redirect

A desktop agent asks the operating system for a free port at launch, so the
port cannot be known at registration. AXIAM follows RFC 8252 §7.3: register the
loopback URI without a port and any port is accepted at request time, for the
`http` scheme on `127.0.0.1`, `[::1]` or `localhost`. Scheme, host, path and
query must still match exactly, and `localhost` and `127.0.0.1` are different
hosts. PKCE is mandatory. See
[Public clients and loopback redirects](../admin/public-clients.md).

### An agent nobody registered: dynamic registration or CIMD

Both are **off by default on every tenant**, and both refuse to turn on until
the tenant has named the audiences such clients may address.

- **Dynamic client registration (RFC 7591)** lets the client create itself at
  `POST /oauth2/register`. It has three modes (`disabled`,
  `initial_access_token`, `anonymous`); prefer `initial_access_token` unless you
  are fronting MCP servers for end users whose clients register themselves. See
  [Dynamic client registration](../admin/dynamic-client-registration.md).
- **Client ID Metadata Documents** let a client present an `https` URL as its
  `client_id`; AXIAM fetches the document published there and materialises a
  shadow client from it. The same desktop client is then the same client at
  every deployment that trusts its publisher, with nothing registered in
  advance. Enabling it means naming whose files you will fetch
  (`cimd.trusted_client_id_domains`, non-empty, `*` refused). See
  [Client ID metadata documents](../admin/client-id-metadata-documents.md).

The end user's consent for such a client is recorded as an OIDC-scope consent
and withdrawn with
`DELETE /api/v1/account/consents/oidc-scopes/{client_id}`.

---

## 2. Act on behalf of a user

There are two shapes, and the registration decides which one an agent can use.

**A local agent with a user's token directly.** A public client runs the code
flow with PKCE and receives a token whose `sub` is the user. There is no `act`
claim: the token says the user, not the agent. Use this when the agent is the
user's own tool on the user's own machine.

**A server-side agent exchanging a user's token (RFC 8693).** A confidential
client that holds the user's access token exchanges it for a narrower one that
records both parties. This is the shape with an auditable "who acted for whom":

```json
{ "sub": "user-uuid", "act": { "sub": "agent-subject" } }
```

The rules, all enforced by the server and summarised from
[Token exchange](../api/token-exchange.md):

| Rule | What it means for an agent |
| --- | --- |
| **An exchange only ever narrows** | No parameter makes the issued token permit more than the subject token did. |
| **`actor_token` selects delegation** | Present it and the token carries `act`; leave it out and you have asked for *impersonation*, which is refused unless the client holds `urn:axiam:params:oauth:grant-type:may-impersonate`. A client without it gets `unauthorized_client`, never a silent downgrade. |
| **`act` chains are capped at depth 3** | Re-exchanging nests `act.act`; a subject token already naming three actors is `invalid_request`. |
| **Scopes are an intersection** | `requested ∩ subject ∩ client-registered`. A scope the subject lacks is `invalid_scope`, not dropped. An empty intersection fails. |
| **`audience` / `resource` must be registered** | The target must be in the exchanging client's `allowed_resources` or be one of AXIAM's own audiences, else `invalid_target`. |
| **Lifetime never exceeds the subject's** | `exp = now + min(subject remaining, configured max exchange lifetime)`. |
| **No refresh token** | Re-run the exchange. |
| **Public clients cannot exchange** | See section 1. |

`act.sub` is the `sub` of the `actor_token` the client presents, which AXIAM
verifies as a valid access token of the same tenant. The usual choice is the
agent's own `client_credentials` token. Every exchange, successful or not, is
audited with the client, subject, actor, scopes, audience and outcome.

Register the exchanging client with the grant and with the targets it may
address:

```bash
curl -X POST https://id.example.com/api/v1/oauth2-clients \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{
        "name": "orders-agent",
        "redirect_uris": [],
        "grant_types": ["client_credentials",
                        "urn:ietf:params:oauth:grant-type:token-exchange"],
        "scopes": ["read:orders"],
        "allowed_resources": ["https://mcp.example.com/mcp"]
      }'
```

### The SDK call

`token_exchange` is §15.1's single operation. The canonical form is
`token_exchange(subject_token, subject_token_type, *, actor_token, scopes,
audience, resource)`: the first two are required and `subject_token_type` has
no default, so pass `urn:ietf:params:oauth:token-type:access_token`
explicitly. The SDKs name it `token_exchange` (Rust, Python, C++),
`tokenExchange` (TypeScript, Java, Kotlin, PHP, Swift), `TokenExchangeAsync`
(C#), `TokenExchange` (Go) and `axiam_token_exchange` (C); the other SDKs
mirror the three below.

```typescript
// TypeScript
const exchanged = await client.tokenExchange({
  subjectToken: userAccessToken,
  subjectTokenType: 'urn:ietf:params:oauth:token-type:access_token',
  actorToken: agentAccessToken,             // present => delegation
  scopes: ['read:orders'],
  resource: 'https://mcp.example.com/mcp',
});
// Read the granted scope and issued token type from the result, and forward
// the exchanged access token on this one outbound call. It is not your session.
```

```python
# Python
exchanged = client.token_exchange(
    user_access_token,
    "urn:ietf:params:oauth:token-type:access_token",
    actor_token=agent_access_token,         # present => delegation
    scopes=["read:orders"],
    resource="https://mcp.example.com/mcp",
)
```

```rust
// Rust: the operation takes one parameters value (TokenExchangeParams)
// populated with the canonical fields above
let exchanged = client.token_exchange(params).await?;
```

**Argument packaging is each SDK's own.** The contract pins the operation name
and the parameter names and order; where an SDK bundles the arguments into one
parameters value (Rust and TypeScript do), the fields carry the canonical names
in that language's casing. Treat the snippets as the shape and the SDK's API
reference as the authority on the exact type and field names.

What §15.2 requires of every SDK, and so what you can rely on:

- **No retry, no rewriting.** `unauthorized_client` and `invalid_scope` are
  surfaced verbatim. An SDK never auto-narrows or downgrades to delegation.
- **The result is not the client's session.** `token_exchange` never adopts the
  returned token as the SDK client's own credentials.
- **`token_type` is read, not assumed.** A client registered for DPoP receives a
  sender-constrained token (`"token_type": "DPoP"`); forwarding it as `Bearer`
  is a bug.
- **`subject_token`, `actor_token` and the result are secrets**, wrapped in the
  SDK's `Sensitive<T>` and never logged.

The same exchange as a raw HTTP call is in
[Token exchange § Request](../api/token-exchange.md#request).

---

## 3. Address the token at one server

A default AXIAM token is addressed at AXIAM (`aud` is `axiam:user` or
`axiam:m2m`). That is the wrong answer once the token is going to an MCP server.
RFC 8707 is how the agent says where it is going: send `resource=<absolute URI>`
and the token's `aud` is that URI, so the receiving server can check that the
token was minted for **it**.

- The client may only name resources in its `allowed_resources`; anything else is
  `invalid_target`. Entries are absolute URIs without a fragment, compared in
  their RFC 3986 §6.2.2 normalised form and **never by prefix**.
- `resource` is honoured on `/oauth2/authorize`, `/oauth2/par`,
  `/oauth2/device_authorization`, the `client_credentials` grant and the token
  exchange (where `audience` is a synonym; if both are sent they must agree).
- **One resource per request.** A token carries a single `aud` string.
- **A grant's audience is fixed when the grant is made.** A refresh token cannot
  be used to re-address a token at a resource the user was never asked about.

Two properties follow that an agent author should plan around:

- **A resource-bound token is not a token for AXIAM.** AXIAM's own REST and gRPC
  surfaces reject it. An agent that must call both AXIAM and an MCP server holds
  two tokens.
- **Binding to a resource and binding to a key compose.** For a token that
  leaves AXIAM's estate, register the client with
  `dpop_bound_access_tokens: true` alongside its `allowed_resources`, so a stolen
  token is useless without the proof key.

Full rules: [Resource indicators](../api/resource-indicators.md).

---

## 4. Be the server an agent calls

If the thing an agent calls is an MCP server, that server is an OAuth 2.0
**resource server**, and **AXIAM does not play that role**. AXIAM issues the
token and mints its `aud`; your server publishes the RFC 9728 document, checks
the audience and emits the challenge. The AXIAM SDK's §28 helpers are the
resource-server half, and the party table in
[Fronting an MCP server with AXIAM](../api/mcp.md) is the picture to hold.

A client's first request carries no credential, so the server answers:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
```

and the client fetches that URL to find AXIAM:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://axiam.example.com"],
  "scopes_supported": ["mcp:read", "mcp:tools"],
  "bearer_methods_supported": ["header"]
}
```

Three operations, all pure local computation with no network I/O (§28.1):

| Canonical operation | Does |
| --- | --- |
| `protected_resource_metadata(resource, authorization_servers, scopes_supported, …)` | Builds and validates the document, and returns it with its `metadata_path` and `metadata_url`. Refuses a bad value at construction rather than repairing it. |
| `serve_protected_resource_metadata(app, metadata)` | Registers the unauthenticated route at the path RFC 9728 §3.1 derives from `resource`. |
| `bearer_challenge(resource_metadata_url, error?, error_description?, scope?)` | Builds the `WWW-Authenticate` **value**. |

Plus one **middleware option**, `resource_metadata_url`, on the §10 guard
(`resourceMetadataUrl` in TypeScript, `ResourceMetadataURL` in Go). Setting it
is what turns the challenge on; with it unset the guard is byte-for-byte what it
was.

```typescript
// TypeScript: publish the document and name it to the guard
const metadata = protectedResourceMetadata(
  'https://mcp.example.com/mcp',          // resource
  ['https://axiam.example.com'],          // authorization_servers: the issuer, verbatim
  ['mcp:read', 'mcp:tools'],              // scopes_supported
);
serveProtectedResourceMetadata(app, metadata);

const session = {
  jwksVerifier,
  tenantHeaderValue: TENANT_ID,
  expectedAudience: 'https://mcp.example.com/mcp',  // must equal `resource`, verbatim
  resourceMetadataUrl: metadata.metadataUrl,        // fed from the helper, not retyped
};
```

```python
# Python
metadata = protected_resource_metadata(
    "https://mcp.example.com/mcp",
    ["https://axiam.example.com"],
    ["mcp:read", "mcp:tools"],
)
serve_protected_resource_metadata(app, metadata)
# then pass metadata.metadata_url as the guard's `resource_metadata_url`
```

```rust
// Rust (Actix-Web): the same three canonical arguments, then the route
let metadata = protected_resource_metadata(RESOURCE, AUTHORIZATION_SERVERS, SCOPES_SUPPORTED)?;
serve_protected_resource_metadata(app, metadata);
// the guard's `resource_metadata_url` is the metadata value's `metadata_url`
```

The same packaging caveat as section 2 applies, and the other SDKs follow the
§28.7 naming map (C and C++ have no `serve_` function; they have no router, and
their READMEs show the adapter). The rules that matter most:

- **`resource` must equal the guard's expected audience**, compared by exact
  string equality, with no normalisation and no trailing-slash tolerance. The SDK
  refuses a configuration where they disagree, or where
  `resource_metadata_url` is set and the audience is not, at startup.
- **Nothing in the document comes from the request.** `resource` and
  `authorization_servers` are configuration; never build them from `Host` or
  `X-Forwarded-*`.
- **`authorization_servers` is the issuer, verbatim, with no query.** With more
  than one tenant behind one deployment, turn on per-tenant path issuers
  (`AXIAM__AUTH__TENANT_ISSUER_PATHS`) so each tenant has a query-free issuer.
- **The challenge is a hint, not a decision.** Every 401 carries it
  (`error="invalid_token"` when a credential was presented, no `error` when none
  was) and says nothing about *why*; the one 403 that carries
  `insufficient_scope` is a `no_grant` decision on a route that named a scope. A
  `denied_by_rule` 403 carries none, because re-authorizing cannot change an
  administrator's decision.
- **A server that announces itself must check `aud`.** Otherwise it has published
  a claim it does not honour, and a token minted for a different server opens it.

A runnable server with the whole handshake is in
[`examples/b7-mcp-server/`](../../examples/b7-mcp-server/). §28 is SHOULD-level
and recorded as implemented in all eleven SDKs; the per-SDK table is §28.10 of
[`sdks/CONTRACT.md`](../../sdks/CONTRACT.md).

---

## 5. Revoke

Revocation is where an agent differs most from a person, because an agent can
hold several kinds of credential at once and each ends differently. Plan around
the table; the last column is the honest one.

| The agent holds… | Ended by | Stops working |
| --- | --- | --- |
| A service account's secret | `rotate-secret`, disabling the account (`PUT /api/v1/service-accounts/{sa_id}` with a non-active status), or deleting it | No new token is issued; a token already in hand lives to its `exp` |
| A bound certificate | `POST /api/v1/certificates/{id}/revoke` | See [PKI](../pki/README.md) for what certificate revocation covers |
| A refresh token (user-authorized agent) | RFC 7009 `POST /oauth2/revoke?tenant_id=<uuid>` by the confidential client that owns it | The refresh token, immediately. **An access token is not revoked** (the endpoint treats it as a no-op) and expires on its own |
| A user's consent to a DCR or CIMD client | The user, `DELETE /api/v1/account/consents/oidc-scopes/{client_id}` | The next authorization asks again. This guide does not claim it recalls tokens already issued |
| An access token carrying `sid` (issued by the code and refresh grants) | The user's session ending | At the next poll of the revocation feed, if the resource server polls it; otherwise at `exp` |
| An **exchanged** token | Nothing: it is short-lived by construction | At `exp`, which is never later than the subject token's |

Four things to design for:

**1. Exchanged tokens carry no `sid`, so the session feed never matches them.**
Revoking the user's session does not retroactively revoke tokens already
exchanged from it, and the exchange itself does not consult session revocation:
a logged-out but unexpired access token can still be exchanged. The window is at
most the subject's remaining lifetime at no more than the subject's privilege,
the same window a revoked access token has everywhere else in the product. Two
habits keep it small: **exchange immediately before the call rather than caching
the result**, and have the operator shorten
`AXIAM__AUTH__ACCESS_TOKEN_LIFETIME_SECS`, which bounds every case above.

**2. `/oauth2/revoke` is for confidential clients.** The same is true of
`/oauth2/introspect` (CONTRACT §12.1 rule 4). A loopback agent registered as a
public client cannot call either; it has no RFC 7009 path, and the levers on the
AXIAM side are the session and the token lifetime.

**3. How a resource server learns.** By default it does not: it verifies the
token locally, which proves the token was issued and has not expired. The
bounded, off-the-hot-path answer is the **session revocation feed**.

- Server: `AXIAM__AUTH__REVOCATION_FEED_ENABLED=true` (default `false`)
  publishes `GET /oauth2/revocations`, the base64url SHA-256 of each session id
  revoked within the last access-token lifetime. It discloses no subject and no
  tenant, and it can only turn an accept into a reject.
- SDK (CONTRACT §10.4, opt-in): the guard polls it off the request path and
  rejects a token whose `sid` appears within one poll interval. An unreachable
  feed behaves exactly as the feature off. The attach points are
  `JwksVerifier::with_revocation_feed` (Rust), `VerifiableSession.revocationFeed`
  (TypeScript) and `JwksVerifier(revocation_feed=…)` (Python); every SDK has
  one, listed in §10.4.1.
- A token with no `sid`, which includes every client-credentials token, every
  RPT and every token exchange, is never matched against the feed.
- On gRPC the default does not re-check the session per request, so a revoked
  session keeps passing until the token expires (up to 15 minutes);
  `AXIAM__GRPC__STRICT_REVOCATION=true` re-checks it. REST re-checks per request.
  See [session-revocation posture](../security-profiles.md#session-revocation-posture-rest-vs-grpc-a4j10).

**4. Introspection is the per-request alternative.** A resource server that
needs an answer for *this token, now* can call `POST /oauth2/introspect` with
confidential-client credentials, at the price of a network round trip per
request, which is why the feed exists.

---

## 6. What AXIAM does not do

Stated so that nobody builds on an assumption:

- **No `may_act` policy.** RFC 8693's `may_act` claim, which lets a subject token
  say who may act for it, is not read anywhere. Who may exchange is decided by
  which clients carry the exchange grant, by that client's registered scopes and
  `allowed_resources`, and by the subject's own privileges. The actor token is
  verified as a valid same-tenant AXIAM access token but is not required to
  belong to the exchanging client, so hand the exchange grant out as you would
  any capability that lets a client speak for your users.
- **No cross-domain delegation.** `actor_token` is refused when the subject token
  comes from an external identity provider, and a token minted from a partner's
  token cannot be exchanged again.
- **No refresh token from an exchange**, and no `refresh_token`, `id_token` or
  SAML subject types.
- **No MCP server on AXIAM's side.** Publishing the RFC 9728 document and
  checking `aud` is the resource server's job, built with the §28 helpers.
- **No separate agent registry.** There is no agent-specific object, console
  page or grant type; the pieces above are what exist, and they are the standard
  ones.

---

## See also

- [Token exchange (RFC 8693)](../api/token-exchange.md): every parameter and
  error, the audience rule, the lifetime cap
- [Resource indicators (RFC 8707)](../api/resource-indicators.md)
- [Fronting an MCP server with AXIAM](../api/mcp.md): the three parties, the
  RFC 9728 document, tenant settings translated from Keycloak's guide
- [Public clients and loopback redirects](../admin/public-clients.md)
- [Dynamic client registration](../admin/dynamic-client-registration.md) and
  [Client ID metadata documents](../admin/client-id-metadata-documents.md)
- [Session-revocation posture](../security-profiles.md#session-revocation-posture-rest-vs-grpc-a4j10)
  and the [revocation feed](../deployment/README.md#session-revocation-feed-optional-t-39--t-143)
- [`sdks/CONTRACT.md`](../../sdks/CONTRACT.md) §15 (token exchange), §10.4 (the
  revocation feed), §28 (MCP resource-server helpers)
- [`examples/b3-mesh-delegation-grpc`](../../examples/b3-mesh-delegation-grpc/README.md)
  and [`examples/b7-mcp-server`](../../examples/b7-mcp-server/)
