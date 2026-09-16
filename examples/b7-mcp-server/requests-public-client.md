# Request shapes — public client and loopback callback (T21.2)

> **This file is a fragment, not the example.** `examples/b7-mcp-server/` is
> owned by T21.7 of
> [`claude_dev/mcp-authorization-server-plan.md`](../../claude_dev/mcp-authorization-server-plan.md),
> which turns this tree into a runnable MCP server with a `walkthrough.sh` and
> a `smoke-test.sh`. Each earlier task deposits the request shape it
> introduces here so that the walkthrough can be assembled from parts that
> have each been exercised against a real server. T21.2's part is below; it is
> asserted end to end in
> `crates/axiam-api-rest/tests/public_client_test.rs`.

An MCP client is a desktop application: it holds no secret and it listens on
whichever port the operating system gives it. Both facts show up in the two
requests below. The normative description is
[`docs/admin/public-clients.md`](../../docs/admin/public-clients.md).

## 1. Register the public client (administrator, once)

```bash
curl -sS -X POST "$AXIAM/api/v1/oauth2-clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "mcp-desktop-client",
        "redirect_uris": ["http://127.0.0.1/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "token_endpoint_auth_method": "none"
      }'
```

The `201` carries **no `client_secret`**. That is the assertion worth making
in the walkthrough: a public registration mints nothing, rather than minting a
secret nobody is told about.

VS Code registers `http://127.0.0.1/callback` and Claude Code registers
`http://localhost/callback`. They are different hosts and AXIAM keeps them
distinct — register the one your client actually uses.

## 2. Authorize, on the port the client happened to get

```
GET $AXIAM/oauth2/authorize
      ?response_type=code
      &client_id=$CLIENT_ID
      &redirect_uri=http%3A%2F%2F127.0.0.1%3A51703%2Fcallback
      &scope=openid+profile
      &state=$STATE
      &code_challenge=$CHALLENGE
      &code_challenge_method=S256
```

Port `51703` was never registered, and is accepted: RFC 8252 §7.3. Everything
else about the URI — scheme, host, path, query — must match the registration
exactly. Omitting `code_challenge` is refused: PKCE is not optional for a
public client.

## 3. Redeem the code with no credential

```bash
curl -sS -X POST "$AXIAM/oauth2/token?tenant_id=$TENANT_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "redirect_uri=http://127.0.0.1:51703/callback" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$VERIFIER"
```

`redirect_uri` must be the URI the browser was actually sent to, port
included: the authorization code stores what was presented, so this
comparison stays exact.

## 4. Refresh, also with no credential

```bash
curl -sS -X POST "$AXIAM/oauth2/token?tenant_id=$TENANT_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN" \
  -d "client_id=$CLIENT_ID"
```

## Negatives worth keeping in the walkthrough

| Request | Answer |
| --- | --- |
| Step 3 with an added `client_secret=…` | `401 invalid_client` — a credential on a public client is a misconfiguration |
| Step 2 without `code_challenge` | redirect carrying `error=invalid_request` |
| Step 3 with `redirect_uri` on a different port from step 2 | `400 invalid_grant` |
| Registering `"token_endpoint_auth_method": "none"` with `"grant_types": ["client_credentials"]` | `400` at registration |
| `POST /oauth2/introspect` as the public client | `401 invalid_client` (RFC 7662 §2.1) |
