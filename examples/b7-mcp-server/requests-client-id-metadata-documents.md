# Request shapes — Client ID Metadata Documents (T21.5)

> **This file is a fragment, not the example.** `examples/b7-mcp-server/` is
> owned by T21.7 of
> [`claude_dev/mcp-authorization-server-plan.md`](../../claude_dev/mcp-authorization-server-plan.md),
> which turns this tree into a runnable MCP server with a `walkthrough.sh` and
> a `smoke-test.sh`. Every other fragment on this page was deposited by the
> task that introduced it; **T21.5 did not deposit one**, so T21.7 mined this
> one from `crates/axiam-api-rest/tests/cimd_test.rs` — every request and
> response below is the shape that test file actually exercises against a
> real server (`a_cimd_client_completes_a_pkce_resource_flow_on_a_random_loopback_port`),
> not an invented one. The normative description is
> [`docs/admin/client-id-metadata-documents.md`](../../docs/admin/client-id-metadata-documents.md).

T21.2 made an MCP client able to complete a code flow with no secret. T21.3
made the token it gets addressed at the MCP server. T21.4 let a client create
its own registration by presenting one to `POST /oauth2/register`. This task
is a third way to arrive at a registration: the client's `client_id` **is** a
URL, and AXIAM fetches what is published there instead of anything being
registered against AXIAM at all.

Throughout: `$AXIAM` is the issuer, `$TENANT` the tenant id, and `$MCP` the
MCP server's resource identifier — for this example,
`https://mcp.example.com/mcp`. `$PUBLISHER` is wherever the client's own
publisher serves its metadata document — for VS Code- and Claude-Code-shaped
clients this is the editor's own update host, not anything AXIAM operates.

## 1. Enable CIMD on the tenant (administrator, once)

Three fields matter beyond the mechanism's own switch, and AXIAM refuses to
store the combination without them: `external_client_allowed_resources` (D3 —
shared with dynamic registration) and `cimd.trusted_client_id_domains` (this
mechanism's own interlock, because the fetch it guards is triggered by an
unauthenticated caller who names the URL).

```bash
curl -sS -X PUT "$AXIAM/api/v1/organizations/$ORG_ID/settings" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
        \"dcr_allowed_scopes\": [\"openid\", \"profile\"],
        \"external_client_allowed_resources\": [\"$MCP\"],
        \"cimd\": {
          \"enabled\": true,
          \"allow_http\": false,
          \"trusted_client_id_domains\": [\"$PUBLISHER\"],
          \"trusted_redirect_domains\": [],
          \"restrict_same_domain\": false,
          \"confidential_only\": false
        }
      }"
```

> The body also carries every existing settings field; they are elided here.
> `trusted_redirect_domains` is empty on purpose — the loopback hosts are
> always allowed, and that is all a desktop MCP client's callback ever needs.
> `restrict_same_domain: false` is **required** for this profile: the
> client's `client_id` is an `https://` URL and its callback is
> `http://127.0.0.1:<port>/…`, which can never share a host with it. See
> [Client ID metadata documents § The two
> profiles](../../docs/admin/client-id-metadata-documents.md#the-two-profiles).
> `allow_http: true` appears only in the test fixture this fragment is mined
> from, because the mock publisher there is a loopback server; a real
> publisher is reached over `https` and this field stays `false`.

## 2. The publisher's document (not an AXIAM request)

AXIAM fetches this from `$PUBLISHER` the first time a request names the
`client_id`; nothing above causes an outbound request by itself. The shape a
real editor's client publishes (`vscode_document` in the test file):

```jsonc
// GET https://$PUBLISHER/client.json
{
  "client_id": "https://$PUBLISHER/client.json",
  "client_name": "Example Editor",
  "redirect_uris": ["http://127.0.0.1:33418/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none",
  "scope": "openid profile"
}
```

`client_id` inside the document must equal the URL it was fetched from
(§ The document rules) — without that, a document copied from another
publisher's host would become that other client.

## 3. Authorize with the URL as `client_id`, naming the MCP server

Nothing about the request shape differs from a pre-registered public client's
— the only difference is that `client_id` is a URL AXIAM has never seen
before this request:

```bash
CLIENT_ID="https://$PUBLISHER/client.json"

curl -sS -i -G "$AXIAM/oauth2/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "redirect_uri=http://127.0.0.1:$PORT/callback" \
  --data-urlencode "scope=openid profile" \
  --data-urlencode "code_challenge=$CHALLENGE" \
  --data-urlencode "code_challenge_method=S256" \
  --data-urlencode "resource=$MCP"
```

```
302 Found
Location: …/consent?…
```

**D4 — consent, unconditionally, on the first authorization.** A client
materialised from somebody else's document is exactly as unrelated a party as
a self-registered one; the redirect goes to the consent screen rather than a
code, whatever scopes were asked for.

```bash
curl -sS -X POST "$AXIAM/api/v1/account/consents/oidc-scopes" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\": \"$CLIENT_ID\", \"scopes\": [\"openid\", \"profile\"]}"
```

The same authorization request, repeated, now returns a code — to the
**port the request actually used**, which need not be the port the document
registered (the T21.2 loopback matcher applies to a CIMD-materialised client
exactly as it does to any other):

```
302 Found
Location: http://127.0.0.1:$PORT/callback?code=…&state=…
```

## 4. Redeem, and read the audience

```bash
curl -sS -X POST "$AXIAM/oauth2/token?tenant_id=$TENANT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$CODE" \
  --data-urlencode "redirect_uri=http://127.0.0.1:$PORT/callback" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "code_verifier=$VERIFIER" \
  --data-urlencode "resource=$MCP"
```

```jsonc
200 OK
{
  "access_token": "…",   // aud: https://mcp.example.com/mcp — the tenant's
                          // list, never anything the document named (D3)
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "…"
}
```

## 5. What the walkthrough owes this fragment

**A tenant that has not enabled CIMD treats the URL as an unknown client,
byte for byte (I1).** Repeat step 3 against a tenant on `cimd.enabled: false`
and the request is refused exactly as an unregistered opaque `client_id`
would be — same status, same body — and the publisher is never contacted.
This is the mandatory regression test in `cimd_test.rs`
(`i1_a_url_client_id_is_an_unknown_client_when_cimd_is_off`), and it is worth
the walkthrough asserting the same pair of requests come back identical.

**An administrator's own client is never overwritten.** If `$CLIENT_ID`
already names a client an administrator created (`managed_by != cimd`), the
document at that URL is ignored entirely — the existing registration, its
secret and its audiences stand. Nothing on this page can reach that case by
accident; it is here so the walkthrough does not have to invent a negative
test that contradicts it.
