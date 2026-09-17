# Request shapes — RFC 8707 resource indicators (T21.3)

> **This file is a fragment, not the example.** `examples/b7-mcp-server/` is
> owned by T21.7 of
> [`claude_dev/mcp-authorization-server-plan.md`](../../claude_dev/mcp-authorization-server-plan.md),
> which turns this tree into a runnable MCP server with a `walkthrough.sh` and
> a `smoke-test.sh`. Each earlier task deposits the request shape it introduces
> here so that the walkthrough can be assembled from parts that have each been
> exercised against a real server. T21.3's part is below; it is asserted end to
> end in `crates/axiam-api-rest/tests/resource_indicators_test.rs`.

T21.2 made the MCP client able to complete a code flow. This task makes the
token it gets *addressed at the MCP server* rather than at AXIAM, which is the
claim in MCP's authorization specification that Keycloak does not implement.
The normative description is
[`docs/api/resource-indicators.md`](../../docs/api/resource-indicators.md).

Throughout: `$MCP` is the MCP server's resource identifier, exactly as its
RFC 9728 protected-resource metadata publishes it — for this example,
`https://mcp.example.com/mcp`.

## 1. Register the resource on the client (administrator, once)

Extends T21.2's registration with one field. A client may name only what its
`allowed_resources` lists; the default is empty, so this step is not optional.

```bash
curl -sS -X POST "$AXIAM/api/v1/oauth2-clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
        \"name\": \"mcp-desktop-client\",
        \"redirect_uris\": [\"http://127.0.0.1/callback\"],
        \"grant_types\": [\"authorization_code\", \"refresh_token\"],
        \"scopes\": [\"openid\", \"profile\"],
        \"token_endpoint_auth_method\": \"none\",
        \"allowed_resources\": [\"$MCP\"]
      }"
```

The `201` echoes `allowed_resources` in its **normalised** form. Worth
asserting in the walkthrough: what comes back is the string the server will
compare, so an operator can check their registration against what the MCP
server publishes without guessing how it was parsed.

An existing client gains the field with a `PATCH`, which replaces the whole
list:

```bash
curl -sS -X PATCH "$AXIAM/api/v1/oauth2-clients/$CLIENT_UUID" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"allowed_resources\": [\"$MCP\"]}"
```

## 2. Authorize, naming the MCP server

T21.2's authorization request plus `resource`. Everything else — PKCE, the
loopback callback on an ephemeral port — is unchanged.

```bash
curl -sS -G "$AXIAM/oauth2/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=http://127.0.0.1:$PORT/callback" \
  --data-urlencode "scope=openid profile" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "resource=$MCP"
```

A `resource` the client has not registered is answered by redirecting to the
client's `redirect_uri` with `error=invalid_target` — worth exercising in the
walkthrough, because it is the failure an operator who forgot step 1 will
actually hit.

## 3. Redeem, and read the audience

```bash
curl -sS -X POST "$AXIAM/oauth2/token?tenant_id=$TENANT_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=http://127.0.0.1:$PORT/callback" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=$MCP"
```

The access token's claims carry `"aud": "$MCP"`. The `resource` on this request
is optional — the code already carries it — but sending it is what an MCP
client library does, and it is the shape the walkthrough should show.

## 4. The two assertions the walkthrough owes T21.3

**The MCP server accepts it.** Present the token to the MCP server; its
resource-server middleware checks `aud` against its own identifier and lets the
call through. That check is configuration on the SDK side
(`sdks/CONTRACT.md` §10.1 row 6), not AXIAM code.

**AXIAM does not.** The same token, presented to AXIAM's own API, is `401`:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' "$AXIAM/api/v1/auth/me" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
# 401
```

This pair is the point of the feature. A token minted for the MCP server opens
the MCP server and nothing of AXIAM's, so handing an MCP server a token is not
handing it an AXIAM credential.

## 5. Refreshing keeps the audience

```bash
curl -sS -X POST "$AXIAM/oauth2/token?tenant_id=$TENANT_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN" \
  --data-urlencode "client_id=$CLIENT_ID"
```

The new access token is minted for `$MCP` again. A refresh naming a *different*
resource is `invalid_target`: a grant's audience is decided when the grant is
made, so a long-lived refresh token cannot be walked over to a service the end
user was never asked about.

## 6. Recommended: bind the token to a key as well

DPoP and the resource indicator are orthogonal, and an MCP token should carry
both. Register `"dpop_bound_access_tokens": true` alongside
`allowed_resources`, send a DPoP proof with the token request, and the token
comes back `"token_type": "DPoP"` with both a `cnf.jkt` and the MCP server's
`aud` — one saying who may present it, the other saying where.
