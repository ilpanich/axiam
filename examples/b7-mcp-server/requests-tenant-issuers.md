# Request shapes — per-tenant path issuers (T21.6)

> **This file is a fragment, not the example.** `examples/b7-mcp-server/` is
> owned by T21.7 of
> [`claude_dev/mcp-authorization-server-plan.md`](../../claude_dev/mcp-authorization-server-plan.md),
> which turns this tree into a runnable MCP server with a `walkthrough.sh` and
> a `smoke-test.sh`. Each earlier task deposits the request shape it introduces
> here so that the walkthrough can be assembled from parts that have each been
> exercised against a real server. T21.6's part is below; it is asserted end to
> end in `crates/axiam-api-rest/tests/tenant_issuer_paths_test.rs`.

T21.3 made the token *addressed at* the MCP server. This task makes the
**authorization server** addressable per tenant, which is what a multi-tenant
deployment needs before an MCP client can find the right one. The normative
description is the issuer section of
[`docs/deployment/README.md`](../../docs/deployment/README.md).

Throughout: `$AXIAM` is the deployment root (`https://id.example.com`),
`$TENANT_ID` the tenant's UUID, and `$ISSUER` the tenant issuer
`$AXIAM/t/$TENANT_ID`.

## 0. The problem this fixes, in one request

Without the flag, the only issuer AXIAM has is the deployment root, and the
tenant travels as a query parameter on each endpoint:

```bash
curl -sS "$AXIAM/.well-known/openid-configuration?tenant_id=$TENANT_ID" \
  | jq -r '.issuer, .token_endpoint'
# https://id.example.com
# https://id.example.com/oauth2/token?tenant_id=6f9619ff-…
```

The endpoints name the tenant; the **issuer does not**, and cannot — RFC 8414
§2 forbids a query component in an issuer identifier. An MCP client is handed
one thing by the MCP server's RFC 9728 metadata, and that thing is an issuer,
so on a multi-tenant deployment it always lands on the default tenant.

## 1. Turn the path form on (operator, once)

```bash
AXIAM__AUTH__OAUTH2_ISSUER_URL=https://id.example.com
AXIAM__AUTH__TENANT_ISSUER_PATHS=true
```

The tenant path is derived, never configured — there is no per-tenant setting.
The server refuses to start if the flag is set without a root issuer, or if the
root issuer carries a path.

## 2. Discovery, three ways

All three return the identical document. The walkthrough should fetch all three
and `diff` them, because "they agree" is the property and one snapshot does not
show it.

```bash
# RFC 8414 §3.1 — insert the well-known segment after the host
curl -sS "$AXIAM/.well-known/oauth-authorization-server/t/$TENANT_ID"

# the same insertion at the OIDC discovery path
curl -sS "$AXIAM/.well-known/openid-configuration/t/$TENANT_ID"

# OpenID Connect Discovery 1.0 §4 — append to the issuer
curl -sS "$ISSUER/.well-known/openid-configuration"
```

```bash
curl -sS "$ISSUER/.well-known/openid-configuration" \
  | jq -r '.issuer, .token_endpoint, .jwks_uri'
# https://id.example.com/t/6f9619ff-…
# https://id.example.com/t/6f9619ff-…/oauth2/token
# https://id.example.com/t/6f9619ff-…/oauth2/jwks
```

No `tenant_id` anywhere. That is the whole point: the issuer is now something a
client can both *verify against* `iss` and *derive a discovery URL from*.

## 3. What the MCP server publishes

The one line that changes in the MCP server's own
`/.well-known/oauth-protected-resource`:

```jsonc
{
  "resource": "https://mcp.example.com/mcp",
  "authorization_servers": ["https://id.example.com/t/6f9619ff-…"],
  "bearer_methods_supported": ["header"]
}
```

With the flag off it would be `["https://id.example.com"]`, and every MCP
client would reach the deployment's default tenant regardless of which tenant
this MCP server serves.

## 4. The code flow, re-based

T21.2's and T21.3's requests with the tenant prefix and **no** `tenant_id`
query. Nothing else changes — the same handlers answer.

```bash
curl -sS -G "$ISSUER/oauth2/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=http://127.0.0.1:$PORT/callback" \
  --data-urlencode "scope=openid profile" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "resource=$MCP"
```

The redirect back to the client carries RFC 9207 `iss=$ISSUER` — the tenant
issuer, which is what the client compares against the document it read.

```bash
curl -sS -X POST "$ISSUER/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=http://127.0.0.1:$PORT/callback" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=$MCP"
```

The access token and the ID token both carry `"iss": "$ISSUER"`, and so does
the Back-Channel Logout token if the client registered one.

## 5. One JWKS, and what follows from it

```bash
diff <(curl -sS "$AXIAM/oauth2/jwks") <(curl -sS "$ISSUER/oauth2/jwks")
# (no output — one key set, many issuers)
```

RFC 8414 permits this and AXIAM does it: there is one signing key per
deployment, not one per tenant. So the signature on a token says nothing about
which tenant it is for, and the walkthrough should show both refusals that
follow:

```bash
# A token minted under tenant A, presented under tenant B.
curl -sS -o /dev/null -w '%{http_code}\n' \
  "$AXIAM/t/$OTHER_TENANT_ID/oauth2/userinfo" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# 401 — the same answer as no credential at all

# Two tenant selectors on one request.
curl -sS "$ISSUER/oauth2/token?tenant_id=$OTHER_TENANT_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN"
# {"error":"invalid_request","error_description":"tenant_id must not be sent
#  as a query parameter on a per-tenant issuer path; the tenant is the path
#  segment"}
```

## 6. The assertion the walkthrough owes T21.6

**The same MCP server, two tenants, two issuers, no crossing.** Run steps 4 and
5 for tenant A and tenant B against one AXIAM, and show that each tenant's
token opens only its own tenant's endpoints. That is the claim a path-shaped
tenant selector has to earn, and it is the reason this task's test file leads
with isolation rather than with discovery.
