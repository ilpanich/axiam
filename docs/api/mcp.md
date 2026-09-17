# Fronting an MCP server with AXIAM

The [Model Context Protocol authorization
specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
makes an MCP server an ordinary OAuth 2.0 **resource server** and delegates
everything else — authentication, consent, token minting — to an ordinary
**authorization server**. This page is about the second half: what AXIAM does
so that an MCP client (Claude Code, VS Code, MCP Inspector) can discover it,
register with it, and obtain a token your MCP server will accept.

**What AXIAM does not do:** publish the MCP server's own RFC 9728 protected-
resource metadata, check an inbound token's `aud`, or emit the
`WWW-Authenticate` challenge that starts an MCP client's discovery. That is
the *resource server's* job — your MCP server's — and it is built with the
AXIAM SDK's §28 helpers (below), not with anything AXIAM the server exposes.
Confusing the two roles is the easiest way to get this wrong: AXIAM issues
the token, your MCP server publishes the document and checks the token.

Read this page top to bottom the first time; after that, its job is mostly to
link to the page that actually has the field you need.

---

## The three parties, and who owns what

| Party | Is | Owns |
| --- | --- | --- |
| AXIAM | the **authorization server** | issuing the token, and minting its `aud` from the RFC 8707 `resource` parameter the client sent |
| Your MCP server | the **resource server** | publishing the RFC 9728 document, checking `aud`, emitting the `WWW-Authenticate` challenge |
| The MCP client | the **client** | reading the challenge, fetching the document, discovering AXIAM, running the code flow |

(`sdks/CONTRACT.md` §28.0 states this the same way — it is the division of
labour the whole section is built on.)

## What AXIAM has that Keycloak's guide asks for

[Keycloak's MCP guide](https://www.keycloak.org/securing-apps/mcp-authz-server)
is the closest thing the ecosystem has to a checklist for "is this
authorization server usable for MCP". AXIAM implements every item on it:

| Requirement | Where |
| --- | --- |
| OAuth 2.1 core, PKCE S256 | Always on; mandatory for public clients |
| RFC 8414 authorization-server metadata at the conventional path | `GET /.well-known/oauth-authorization-server` (alongside `/.well-known/openid-configuration`) |
| Public clients with PKCE | [`../admin/public-clients.md`](../admin/public-clients.md) |
| Loopback redirect with a random port (RFC 8252 §7.3) | Same page |
| RFC 8707 resource indicators, `aud` bound to the MCP server | [`resource-indicators.md`](resource-indicators.md) — AXIAM implements this properly; Keycloak's own guide documents a scope-and-audience-mapper workaround because it does not |
| RFC 7591 dynamic client registration | [`../admin/dynamic-client-registration.md`](../admin/dynamic-client-registration.md) |
| OAuth Client ID Metadata Document (CIMD) | [`../admin/client-id-metadata-documents.md`](../admin/client-id-metadata-documents.md) |
| An issuer an MCP client can discover for the right tenant | [Per-tenant path issuers](../deployment/README.md#the-issuer-and-per-tenant-path-issuers-optional-t216) |

Everything in that table is **opt-in**. A deployment that enables none of it
behaves exactly as it did before any of this existed.

---

## The RFC 9728 document your MCP server publishes

An MCP client's first request carries no credential. What comes back is what
tells it where to go:

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
```

and fetching that URL returns the document that names AXIAM:

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://axiam.example.com"],
  "scopes_supported": ["mcp:read", "mcp:tools"],
  "bearer_methods_supported": ["header"]
}
```

Both are built and served by your MCP server's own SDK middleware —
`sdks/CONTRACT.md` §28 ("MCP Resource-Server Helpers") is the normative
specification, and the full 401/discovery/403 sequence with exact wire
examples is
[`../../examples/b7-mcp-server/requests-protected-resource-metadata.md`](../../examples/b7-mcp-server/requests-protected-resource-metadata.md).
Three canonical operations, present in every AXIAM SDK that implements §28:

| Operation | Does |
| --- | --- |
| `protected_resource_metadata(...)` | Builds and validates the document above (pure computation, no network I/O) |
| `serve_protected_resource_metadata(app, metadata)` | Registers the unauthenticated route it is served from, at the path RFC 9728 §3.1 derives from `resource` |
| `bearer_challenge(resource_metadata_url, error?, ...)` | Builds the `WWW-Authenticate` **value** — never the whole response — for the guard to attach |

**`resource` MUST equal the `expected_audience` your guard is configured
with**, and `authorization_servers` MUST name AXIAM's issuer with no query or
fragment (§28.2 rules 4 and 9). Both are configuration, never derived from the
inbound request — a document built from a `Host` header is a document an
attacker can point at an authorization server of their choosing.

## The SDK middleware configuration

Everything above is one option on the resource-server guard your SDK already
has (`sdks/CONTRACT.md` §10, §11):

```ts
// TypeScript — the shape every language's §28.5 config maps onto
const session = {
  jwksVerifier,
  tenantHeaderValue: TENANT_ID,
  expectedAudience: "https://mcp.example.com/mcp",   // = the resource, verbatim
  // resourceMetadataUrl set once §28 lands in the published package — see
  // examples/b7-mcp-server/README.md for what this example does today.
};
```

Two rules from `sdks/CONTRACT.md` §28.5 that are easy to get backwards:

- **Setting `resource_metadata_url` is what turns the challenge on.** Leave it
  unset and the guard's behaviour towards a request is byte-for-byte what it
  is without §28 — no header, no status change. This is the same "off means
  absent" posture every other opt-in AXIAM feature holds to.
- **`expected_audience` MUST be set whenever `resource_metadata_url` is.** A
  resource server that publishes "tokens for me carry this `aud`" and does not
  then check `aud` has published a claim it does not honour. The SDK refuses
  the configuration at startup rather than at the first request.

`expected audience` is exactly the string your MCP server names as `resource`
— see [Resource indicators](resource-indicators.md) for how that string
becomes the token's `aud` in the first place, and note the two are compared
by exact string equality, never normalised (§28.5 rule 3).

**DPoP or mTLS is the recommended posture for a token leaving AXIAM's own
estate.** Sender-constraining (RFC 9449 / RFC 8705) binds a token to a key;
RFC 8707 binds it to a resource; the two compose freely, and a stolen
bearer-only MCP token is otherwise usable by whoever holds it. Register the
client with `dpop_bound_access_tokens: true` alongside `allowed_resources` —
see [Resource indicators § Sender constraining is
orthogonal](resource-indicators.md#sender-constraining-is-orthogonal).

**Nothing in §28 is a source of truth about a token.** The document is a
claim your resource server publishes about itself, and the challenge is a
hint to a client that failed. The decision of whether a request is authorized
is §10.1's and §11's alone; an implementation that lets either of the §28
pieces influence an accept/reject has inverted the section.

## The four things that trip this up

1. **Discovery advertises `token_endpoint_auth_methods_supported: [..., "none"]`
   unconditionally.** This is what makes a public client possible at all, but
   the maintainer's ruling that admitted it is conditional: it holds
   *provided it does not affect the OIDF conformance tests*, and **that
   condition has not yet been checked** — the FAPI 2.0 discovery module that
   would catch a problem
   (`fapi2-security-profile-final-discovery-end-point-verification`) has not
   been run against this change. Do not read this page, or any other, as
   asserting FAPI 2.0 conformance is unaffected by advertising `none`; that is
   an open question for [T21.8](../../claude_dev/mcp-authorization-server-plan.md)
   to close.
2. **`http://[::1]/…` cannot be registered**, through any endpoint, as a
   pre-existing validator gap that predates this work and is deliberately left
   alone (fixing it would let a currently-refused registration succeed).
   Nothing here needs it: Claude Code registers `http://localhost/callback`,
   VS Code registers `http://127.0.0.1/callback`, and the two hosts are not
   interchangeable — register whichever your client actually uses. See
   [Public clients § `localhost` and `127.0.0.1` are not
   interchangeable](../admin/public-clients.md#localhost-and-127001-are-not-interchangeable).
3. **`dcr_allowed_scopes` refuses `address` and `phone`.** Not an oversight —
   a self-registered or CIMD-materialised client already carries a forced
   consent record of its own, and layering a GDPR-sensitive-scope consent
   record on top of it would need two consent records for one client, with no
   good answer for what the user is actually shown. See [Dynamic client
   registration § Sensitive scopes are
   refused](../admin/dynamic-client-registration.md#sensitive-scopes-are-refused).
4. **With per-tenant path issuers on, the eleven re-based OAuth2 endpoints are
   not in `openapi.json`.** utoipa binds one path per handler function, and
   documenting `/t/{tenant_id}/oauth2/token` and its ten siblings would have
   meant eleven duplicate handlers — which the feature's own design forbids.
   The three discovery forms *are* documented; the deployment page names the
   other eleven in full, because the spec cannot. See [Per-tenant path
   issuers](../deployment/README.md#the-issuer-and-per-tenant-path-issuers-optional-t216).

## The D3 warning: name your audiences before you open the door

Both dynamic registration's `anonymous` mode and CIMD hand a `client_id` to a
party AXIAM did not vet. Neither lets that party choose its own token
audiences — a materialised client always inherits the tenant's
`external_client_allowed_resources`, never anything it names itself (D3, in
the plan's terms). An **empty** list is not "no audiences": it leaves such a
client able to obtain today's `axiam:user` tokens, which are exactly the
tokens **AXIAM's own APIs accept**. Both mechanisms refuse to turn on while
the list is empty. Name the MCP servers this tenant fronts first — see
[Dynamic client registration § The D3
warning](../admin/dynamic-client-registration.md#the-d3-warning-audiences) and
[Client ID metadata documents §
D3](../admin/client-id-metadata-documents.md#d3--you-must-name-your-audiences-first).

---

## Tenant settings, translated from Keycloak's guide

Keycloak's MCP guide configures a realm with client registration open, a
loopback redirect URI, and an audience mapper. The same intent, in AXIAM
settings, across all three ways a client can arrive:

| Keycloak | AXIAM (pre-registered) | AXIAM (dynamic registration) | AXIAM (CIMD) |
| --- | --- | --- | --- |
| Client registration policy | — (admin creates the client) | `dynamic_registration: "anonymous"` | `cimd.enabled: true` |
| `token_endpoint_auth_method` | `"none"` at registration | `"none"` (registered by the client) | forced `none` unless `cimd.confidential_only` |
| Redirect URI `http://localhost:6274/*` | register what the client uses, port omitted (RFC 8252 §7.3) | nothing — the client registers its own URI, any port accepted | nothing — loopback is always allowed regardless of `cimd.trusted_redirect_domains` |
| Allowed scopes | `scopes: [...]` on the client | `dcr_allowed_scopes: ["openid", "profile"]` | same field — CIMD reuses it |
| Audience mapper adding the MCP server to `aud` | `allowed_resources: ["https://mcp.example.com/mcp"]`, client sends `resource=` | `external_client_allowed_resources: [...]` (D3) | same field (D3) |
| — | — | `dcr_max_clients`, `dcr_unused_client_ttl_days`, and a one-hour sweep of never-authorized registrations in `anonymous` mode — no Keycloak equivalent | `cimd.trusted_client_id_domains` (**required**, non-empty, and `*` is refused) — no Keycloak equivalent; `dcr_max_clients` and `dcr_unused_client_ttl_days` bound shadow rows too |

Keycloak's audience mapper is a workaround for not implementing RFC 8707;
AXIAM mints the audience from the `resource` parameter the client actually
sends, so a token is addressed at one MCP server rather than at whatever the
mapper happened to be configured with.

**A CIMD desktop profile needs one more setting Keycloak's guide does not
have an analogue for:** `cimd.restrict_same_domain: false`. A desktop
client's `client_id` is an `https` URL but its redirect lands on
`http://127.0.0.1:<port>/…`, which can never share a host with it — leaving
the default `true` would refuse every desktop CIMD client, every time. See
[Client ID metadata documents § The two
profiles](../admin/client-id-metadata-documents.md#the-two-profiles).

### The client-specific values

| Client | Loopback host it registers | `client_id` (CIMD) |
| --- | --- | --- |
| MCP Inspector | `127.0.0.1` (default port `6274`, any port accepted) | registers per-instance; no published CIMD identity as of this writing |
| VS Code | `127.0.0.1` | consult VS Code's own MCP client documentation for its published `client_id`, if any, before setting `cimd.trusted_client_id_domains` |
| Claude Code | `localhost` | consult Claude Code's own MCP client documentation for its published `client_id`, if any, before setting `cimd.trusted_client_id_domains` |

Take the publisher host from the client's own documentation, not from this
page — `cimd.trusted_client_id_domains` is a decision about whose files your
deployment will fetch, and a stale value copied from a doc is exactly the
kind of mistake that field exists to make deliberate. See [What it costs
you](../admin/client-id-metadata-documents.md#what-it-costs-you).

---

## One worked example per mode

Each of the three ways a client can obtain a token addressed at your MCP
server, in full, with the exact request/response shapes each implementing
task tested against a real server:

### Pre-registered (an administrator creates the client)

1. Register a public client with `allowed_resources` naming your MCP server —
   [`../../examples/b7-mcp-server/requests-public-client.md`](../../examples/b7-mcp-server/requests-public-client.md).
2. Authorize with `resource=` and redeem the code —
   [`../../examples/b7-mcp-server/requests-resource-indicators.md`](../../examples/b7-mcp-server/requests-resource-indicators.md).

Use this when you already have an out-of-band way to hand each MCP client a
`client_id` (a config file you ship, a pinned value in an admin console).

### Dynamic client registration (the client creates itself)

1. Enable `dynamic_registration` and set `external_client_allowed_resources`
   (D3) —
   [`../../examples/b7-mcp-server/requests-dynamic-registration.md`](../../examples/b7-mcp-server/requests-dynamic-registration.md).
2. The client discovers `registration_endpoint`, registers itself, passes the
   forced consent screen once, and completes the same PKCE + `resource` flow.

Use this when clients arrive without any admin action at all — the MCP
Inspector case Keycloak's guide is built around.

### Client ID Metadata Documents (the client is the same everywhere)

1. Enable `cimd.enabled`, name the publisher in
   `cimd.trusted_client_id_domains`, and turn off `cimd.restrict_same_domain`
   for a desktop profile —
   [`../../examples/b7-mcp-server/requests-client-id-metadata-documents.md`](../../examples/b7-mcp-server/requests-client-id-metadata-documents.md).
2. The client presents its `https://` URL as `client_id`; AXIAM fetches the
   document, materialises a shadow client, forces consent, and the rest of
   the flow is identical to the other two modes.

Use this when the client is a publisher-distributed application (an editor,
an IDE extension) that should be the same client at every AXIAM deployment it
talks to, with nothing registered anywhere in advance.

### Per-tenant issuers, in any of the three modes

A single-tenant deployment needs nothing further: one issuer already means
one tenant. A deployment that fronts MCP servers for **more than one** tenant
should turn on `AXIAM__AUTH__TENANT_ISSUER_PATHS`, so each tenant gets a
query-free issuer an MCP client can both verify `iss` against and derive
discovery from — see
[`../../examples/b7-mcp-server/requests-tenant-issuers.md`](../../examples/b7-mcp-server/requests-tenant-issuers.md)
and [the deployment
page](../deployment/README.md#the-issuer-and-per-tenant-path-issuers-optional-t216)
for what changes and what does not.

---

## The runnable example

[`examples/b7-mcp-server/`](../../examples/b7-mcp-server/) is a complete MCP
server on the official `@modelcontextprotocol/sdk` streamable-HTTP transport,
guarded by the AXIAM TypeScript SDK's resource-server middleware, fronted by a
bootstrapped AXIAM. Its `walkthrough.sh` drives the whole handshake — 401 →
discovery → registration (in each of the three modes) → PKCE + `resource` →
token → tool call — over plain curl, in the style of
[`examples/b1-deny-override`](../../examples/b1-deny-override/README.md); its
`smoke-test.sh` proves the server actually runs; its README has the
copy-paste configuration for MCP Inspector, Claude Code and VS Code.

---

## See also

- [Public clients and loopback redirects](../admin/public-clients.md) — `none`
  and RFC 8252 §7.3
- [Resource indicators](resource-indicators.md) — RFC 8707, `allowed_resources`,
  and why AXIAM's own APIs refuse an MCP-bound token
- [Token exchange § Audience](token-exchange.md#audience) — the RFC 8693
  grant's own audience rule, rewritten for `allowed_resources`
- [Dynamic client registration](../admin/dynamic-client-registration.md) —
  RFC 7591, the three modes, the D3 warning
- [Client ID metadata documents](../admin/client-id-metadata-documents.md) —
  the draft this implements, the URL and document rules, the two profiles
- [Per-tenant path issuers](../deployment/README.md#the-issuer-and-per-tenant-path-issuers-optional-t216) —
  the issuer form a multi-tenant MCP deployment needs
- [`sdks/CONTRACT.md`](../../sdks/CONTRACT.md) §28 — the normative
  resource-server helper specification every SDK implements this against
- [`examples/b7-mcp-server/`](../../examples/b7-mcp-server/) — the runnable
  example this page describes
