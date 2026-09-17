# Request shapes — RFC 7591 dynamic client registration (T21.4)

> **This file is a fragment, not the example.** `examples/b7-mcp-server/` is
> owned by T21.7 of
> [`claude_dev/mcp-authorization-server-plan.md`](../../claude_dev/mcp-authorization-server-plan.md),
> which turns this tree into a runnable MCP server with a `walkthrough.sh` and
> a `smoke-test.sh`. Each earlier task deposits the request shape it introduces
> here so that the walkthrough can be assembled from parts that have each been
> exercised against a real server. T21.4's part is below; it is asserted end to
> end in `crates/axiam-api-rest/tests/dynamic_registration_test.rs`.

T21.2 made an MCP client able to complete a code flow, and T21.3 made the token
it gets addressed at the MCP server. Both still needed an administrator to
create the client first — which is exactly the step MCP Inspector, Claude Code
and VS Code do not have. This task removes it: the client creates itself.

The normative description, including every policy field and the D3 warning, is
[`docs/admin/dynamic-client-registration.md`](../../docs/admin/dynamic-client-registration.md).

Throughout: `$AXIAM` is the issuer, `$TENANT` the tenant id, and `$MCP` the MCP
server's resource identifier — for this example,
`https://mcp.example.com/mcp`.

## 1. Enable registration on the tenant (administrator, once)

The one step that is not optional, and the one an operator must think about.
`external_client_allowed_resources` is what a self-registered client's
`allowed_resources` becomes, so it is what decides which audiences a stranger's
client can obtain a token for. AXIAM refuses to store `anonymous` while it is
empty.

```bash
curl -sS -X PUT "$AXIAM/api/v1/organizations/$ORG_ID/settings" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
        \"dynamic_registration\": \"anonymous\",
        \"dcr_allowed_scopes\": [\"openid\", \"profile\"],
        \"dcr_allowed_redirect_hosts\": [],
        \"external_client_allowed_resources\": [\"$MCP\"],
        \"dcr_max_clients\": 20,
        \"dcr_unused_client_ttl_days\": 30
      }"
```

> The body also carries every existing settings field; they are elided here.
> `dcr_allowed_redirect_hosts` is empty on purpose: the loopback hosts are
> always allowed, and a desktop MCP client wants nothing else.

## 2. Discover the endpoint (the MCP client)

This is what makes the whole flow automatic. The client is given one URL and
reads the rest.

```bash
curl -sS "$AXIAM/.well-known/oauth-authorization-server?tenant_id=$TENANT" \
  | jq -r '.registration_endpoint'
```

```
https://id.example.com/oauth2/register?tenant_id=…
```

A tenant that has not enabled registration has **no such member** — the
document is byte-identical to the one it served before this task — and a client
reading it knows to ask its user for a pre-registered `client_id` instead.

## 3. Register (the MCP client, unauthenticated)

The shape MCP Inspector actually sends.

```bash
REGISTERED=$(curl -sS -X POST "$AXIAM/oauth2/register?tenant_id=$TENANT" \
  -H "Content-Type: application/json" \
  -d '{
        "client_name": "MCP Inspector",
        "redirect_uris": ["http://127.0.0.1:6274/oauth/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": "openid profile"
      }')
CLIENT_ID=$(echo "$REGISTERED" | jq -r '.client_id')
```

```jsonc
201 Created
{
  "client_id": "…",
  "client_id_issued_at": 1789200000,
  "client_name": "MCP Inspector",
  "redirect_uris": ["http://127.0.0.1:6274/oauth/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid profile"
}
```

No `client_secret`: a `none` registration mints none, so the member is absent
rather than empty. No `registration_access_token` or `registration_client_uri`
either — RFC 7592's configuration endpoint is deferred, and promising an
endpoint that does not exist is worse than not promising one.

Note what the response does **not** echo back, because the request did not get
to decide it: the client's `allowed_resources` is `["$MCP"]`, from step 1.

### With an initial access token

On a tenant in `initial_access_token` mode, an administrator mints one first:

```bash
HANDLE=$(curl -sS -X POST "$AXIAM/api/v1/oauth2-clients/registration-tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "mcp-inspector-demo", "expires_in_hours": 24}' \
  | jq -r '.initial_access_token')
```

and the same registration carries it:

```bash
curl -sS -X POST "$AXIAM/oauth2/register?tenant_id=$TENANT" \
  -H "Authorization: Bearer $HANDLE" \
  -H "Content-Type: application/json" \
  -d '{ … as above … }'
```

The handle is single-use. A second registration on it is `403`.

## 4. Consent, once, per end user

The first authorization for a self-registered client is a redirect to the
consent screen rather than a code — it is an application nobody at this
deployment vetted, so the end user is asked before it may act as them.

```bash
curl -sS -i -G "$AXIAM/oauth2/authorize" \
  -H "Authorization: Bearer $USER_TOKEN" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=http://127.0.0.1:6274/oauth/callback" \
  --data-urlencode "scope=openid profile" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "resource=$MCP"
```

```
302 Found
Location: …/consent?…
```

The user approves, which the SPA records through the ordinary account-page
endpoint:

```bash
curl -sS -X POST "$AXIAM/api/v1/account/consents/oidc-scopes" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"$CLIENT_ID\", \"scopes\": [\"openid\", \"profile\"]}"
```

and can withdraw it from the same page later:

```bash
curl -sS -X DELETE "$AXIAM/api/v1/account/consents/oidc-scopes/$CLIENT_ID" \
  -H "Authorization: Bearer $USER_TOKEN"
```

## 5. The flow T21.2 and T21.3 already built

From here nothing is new. The same authorization request now returns a code,
and the token request redeems it with no secret and gets a token whose `aud` is
the MCP server:

```bash
curl -sS -X POST "$AXIAM/oauth2/token?tenant_id=$TENANT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=http://127.0.0.1:6274/oauth/callback" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=$MCP"
```

```jsonc
{
  "access_token": "…",   // aud: https://mcp.example.com/mcp
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "…"
}
```

## 6. The refusals worth showing in a walkthrough

| Request | Answer |
| --- | --- |
| Registration against a tenant that has not enabled it | `403 invalid_request` |
| `initial_access_token` mode with no bearer, a wrong one, or a spent one | `403 invalid_request` — all three identical, so nothing can be probed |
| `"software_statement": "…"` | `400 invalid_software_statement` |
| `"grant_types": ["authorization_code", "client_credentials"]` | `400 invalid_client_metadata` |
| `"scope": "openid admin"` when the tenant offers only `openid profile` | `400 invalid_client_metadata` |
| A redirect URI on a host outside `dcr_allowed_redirect_hosts` | `400 invalid_redirect_uri` |
| The 21st registration on a tenant with `dcr_max_clients: 20` | `403 invalid_request` |
| The 6th registration in a minute from one IP | `429` |
| `resource` naming anything but `$MCP` | `invalid_target`, redirected |
