# Request shapes — RFC 9728 protected-resource metadata and the bearer challenge (T21.9)

> **This file is a fragment, not the example.** `examples/b7-mcp-server/` is
> owned by T21.7 of
> [`claude_dev/mcp-authorization-server-plan.md`](../../claude_dev/mcp-authorization-server-plan.md),
> which turns this tree into a runnable MCP server with a `walkthrough.sh` and
> a `smoke-test.sh`. Each earlier task deposits the request shape it introduces
> here. T21.9's part is below.

**Every request on this page is against the MCP server, not against AXIAM.**
That is the whole point of the section it comes from: AXIAM is the
authorization server and implements none of this. The normative description is
[`sdks/CONTRACT.md`](../../sdks/CONTRACT.md) §28; the code that answers these
requests is the AXIAM SDK's resource-server middleware, which T21.9b writes in
TypeScript and T21.9c ports to the other ten.

Throughout: `$MCP` is the MCP server's base URL and `$AXIAM` is the AXIAM
deployment's issuer. For this example, `$MCP` is `https://mcp.example.com` and
the resource identifier is `https://mcp.example.com/mcp` — the same `$MCP`
value [`requests-resource-indicators.md`](requests-resource-indicators.md)
sends as the RFC 8707 `resource` parameter, and the same value the middleware
checks `aud` against. The three must be one string; §28.5 rule 3 is why.

## 1. The 401 that starts the handshake

The MCP client's first call carries no credential. What comes back is what
tells it where to go — and, before T21.9, an AXIAM-guarded MCP server returned
a 401 with no `WWW-Authenticate` header at all, leaving the client nothing to
discover from.

```bash
curl -sS -i -X POST "$MCP/mcp" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
Content-Type: application/json

{"error":"authentication_failed","message":"..."}
```

Two things worth asserting in the walkthrough, because both are rules rather
than accidents:

- **No `error` parameter.** The request carried no authentication information,
  so RFC 6750 §3 says not to name one. A request that presents an *expired*
  token gets the same 401 with `error="invalid_token"` added, and nothing else
  added — expired, wrong tenant, wrong audience and bad signature are one
  answer, deliberately.
- **The JSON body is unchanged.** §28 adds a header. It does not touch the
  status or the body the SDK's guard already returned.

## 2. The document the challenge points at

```bash
curl -sS "$MCP/.well-known/oauth-protected-resource/mcp"
```

```json
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://axiam.example.com"],
  "scopes_supported": ["mcp:read", "mcp:tools"],
  "bearer_methods_supported": ["header"]
}
```

The path is derived from the resource identifier, not chosen: RFC 9728 §3.1
inserts `/.well-known/oauth-protected-resource` between the authority and the
path, so a resource of `https://mcp.example.com/mcp` publishes at
`/.well-known/oauth-protected-resource/mcp` and one of
`https://mcp.example.com` publishes at the bare well-known path.

**It must answer without a credential.** The walkthrough should fetch it with
no `Authorization` header and assert `200` — a metadata document behind the
guard cannot start the handshake it exists to start.

From here the client has an issuer and the rest of the walkthrough takes over:
`GET $AXIAM/.well-known/oauth-authorization-server` (T21.1), then the public
client and loopback callback of
[`requests-public-client.md`](requests-public-client.md), then the PKCE code
flow carrying `resource=https://mcp.example.com/mcp` from
[`requests-resource-indicators.md`](requests-resource-indicators.md).

## 3. The 403 that asks for a scope

A tool the caller's token may not reach answers `403`. Where the route names a
scope and the AXIAM decision came back `no_grant` — nothing matched, as opposed
to an administrator's explicit deny — the refusal names the scope to ask for:

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
Content-Type: application/json

{"error":"authorization_denied","message":"..."}
```

`insufficient_scope` is in the header and `authorization_denied` is in the
body, and they are not two spellings of one thing: the body is the SDK's §11
error taxonomy, unchanged, and the header is the RFC 6750 hint. A deny that
came back `denied_by_rule` carries **no** `WWW-Authenticate` header, because
re-authorizing cannot satisfy a decision an administrator has already made and
a challenge would send the client round the loop to the same 403.

## 4. The assertion this fragment owes T21.9

**Announcing yourself obliges you to check.** A resource server that publishes
`"resource": "https://mcp.example.com/mcp"` and does not verify that an inbound
token's `aud` is that string has published a claim it does not honour — and a
token minted for a different MCP server opens it. §28.5 rule 2 makes the
audience check mandatory whenever the challenge is configured, and the SDK
refuses the configuration at startup otherwise. The walkthrough proves it from
the outside: the token from
[`requests-resource-indicators.md`](requests-resource-indicators.md) §3 is
accepted, and an `axiam:user` token — a perfectly valid AXIAM token that simply
was not minted for this resource — is `401`.
