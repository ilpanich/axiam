# Public clients and loopback redirects

AXIAM can register an OAuth2 client that holds **no credential at all**
(`token_endpoint_auth_method: "none"`, RFC 6749 §2.1) and accept the
**ephemeral loopback port** such a client listens on (RFC 8252 §7.3). The two
together are what a desktop application needs: Claude Code, VS Code and the
MCP Inspector ship their configuration to the user, so a secret in it is a
secret the user has, and they take whichever port the operating system gives
them at launch.

Both are opt-in per client. **A deployment that registers no public client
behaves exactly as it did before** — the loopback rule applies only to
registered `http` loopback URIs, every other redirect URI keeps the
byte-for-byte comparison it has always had, and a client registered for a
credential that omits it is still refused.

---

## When to register a public client

Register `none` when the client **cannot** keep a secret:

| Client | Why |
| --- | --- |
| A desktop or CLI application (Claude Code, an MCP client, a terminal tool) | The binary and its configuration are on the user's machine |
| A single-page application | Everything it holds is readable in the browser |
| A mobile application | The bundle is extractable from the device |

Register a confidential client — the default, `client_secret_post` — for
anything that runs on a server you control. A public registration is not a
convenience for skipping secret management: it removes a credential, and PKCE
is what replaces what that credential was protecting.

```bash
curl -X POST "https://id.example.com/api/v1/oauth2-clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "claude-code",
        "redirect_uris": ["http://localhost/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
        "scopes": ["openid", "profile"],
        "token_endpoint_auth_method": "none"
      }'
```

```jsonc
201 Created
{
  "id": "…",
  "client_id": "oa_…",
  // no `client_secret` member: there is none, and an empty string would read
  // as a secret that happens to be empty
  "name": "claude-code",
  "redirect_uris": ["http://localhost/callback"],
  …
}
```

The stored `client_secret_hash` is empty because nothing was minted. This is
deliberate: a client whose registration says it holds no credential must not
also be issued one it was told to discard.

---

## The token endpoint's authentication methods

| `token_endpoint_auth_method` | Credential | FAPI 2.0 |
| --- | --- | --- |
| `client_secret_post` (default) | Shared secret, in the request body (RFC 6749 §2.3.1) | Refused |
| `client_secret_basic` | The same shared secret, in the `Authorization` header | Refused |
| `tls_client_auth` | A certificate a trusted CA issued, matched against a registered subject DN or SAN (RFC 8705 §2.1) | Accepted |
| `self_signed_tls_client_auth` | The certificate itself, matched by SHA-256 thumbprint (RFC 8705 §2.2) | Accepted |
| `private_key_jwt` | A signed assertion, verified against a registered `jwks` or `jwks_uri` (RFC 7523 §2.2) | Accepted |
| `none` | **Nothing.** PKCE is required instead (RFC 7636) | Refused |

All six are advertised in
`token_endpoint_auth_methods_supported` at
`/.well-known/openid-configuration`. That list describes what the
**deployment** can serve, never what any one client may use — the
registration decides that, and `none` is only ever reached by a registration
that named it.

---

## What a public registration is refused

A registration that says `none` and something else at the same time is
refused at `POST /api/v1/oauth2-clients` with `400` and a message naming the
contradiction:

| Also registered | Why it is refused |
| --- | --- |
| `grant_types` containing `client_credentials` | The grant rests on the client's own credential, and a public client's only identifier is a `client_id` that travels in every authorization request it makes |
| `grant_types` containing `urn:ietf:params:oauth:grant-type:token-exchange` | Same, and an exchange must be attributable to somebody |
| `profile: "fapi2"` | FAPI 2.0 §5.3.1.1 admits only `private_key_jwt` and mutual TLS |
| `tls_client_auth_subject_dn`, `tls_client_auth_san_dns`, `tls_client_auth_san_uri` | A credential AXIAM would never check: the public arm of the token endpoint reads none |
| `self_signed_tls_client_auth_thumbprints` | Same |
| `jwks` or `jwks_uri` | Same |

Three more refusals happen later, at request time:

* **A presented credential.** A public client that sends a `client_secret`, an
  `Authorization: Basic` header, a `client_assertion` or a client certificate
  is refused `invalid_client`. A credential on a public client is a
  misconfiguration — usually a client pointed at the wrong registration — not
  a bonus, and accepting it would make the registration an OR over "nothing"
  and "whatever arrived".
* **Introspection.** `POST /oauth2/introspect` refuses a public client:
  RFC 7662 §2.1 requires an authenticated caller, and a `client_id` that
  appears in every browser redirect is not one. **Revocation is not refused** —
  RFC 7009 §2.1 contemplates public clients, and a revocation only ever
  reaches a token the caller already holds.
* **The UMA ticket grant.** Same reasoning as token exchange; an RPT must be
  attributable.

**A confidential client never becomes public by omission.** A client
registered for `client_secret_post` that sends no secret is still
`invalid_client`, with the same answer an unknown `client_id` gets. The
`token_endpoint_auth_method` also cannot be changed across that line by an
update: the secret cannot follow the change in either direction, so AXIAM
refuses the patch and asks you to register the client you actually want.

---

## PKCE is not optional

For a public client, PKCE (RFC 7636, `S256` — AXIAM refuses `plain`) is
required **at both ends of the flow**:

* `/oauth2/authorize` refuses an authorization request with no
  `code_challenge`, redirecting `error=invalid_request` to the registered
  callback;
* `/oauth2/token` refuses to redeem a code that carries no stored challenge
  with `invalid_grant`, whatever that code's history.

The second gate exists for codes the first one cannot have issued — a row
predating a registration change, for instance. Without it, the code alone
would be the credential, which is the attack PKCE replaces the client secret
with.

---

## Loopback redirect URIs (RFC 8252 §7.3)

A desktop client asks the operating system for a free port at launch, so the
port is not knowable when the client is registered. RFC 8252 §7.3 requires an
authorization server to

> allow any port to be specified at the time of the request for loopback IP
> redirect URIs

and AXIAM does, for registered URIs whose scheme is `http` and whose host is
`127.0.0.1`, `[::1]` or `localhost`.

**The allowance widens the port and nothing else.** Scheme, host, path, query
and fragment must still be identical to what was registered:

| Registered | Presented | |
| --- | --- | --- |
| `http://127.0.0.1/callback` | `http://127.0.0.1:51703/callback` | accepted |
| `http://127.0.0.1:8080/callback` | `http://127.0.0.1:51703/callback` | accepted — the rule is about loopback URIs, not port-less ones |
| `http://127.0.0.1/callback` | `http://localhost:51703/callback` | **refused** |
| `http://127.0.0.1/callback` | `http://127.0.0.1:51703/callback/` | **refused** |
| `http://127.0.0.1/callback` | `http://127.0.0.1:51703/callback?next=…` | **refused** |
| `http://127.0.0.1/callback` | `http://127.0.0.2:51703/callback` | **refused** |
| `https://localhost/callback` | `https://localhost:8443/callback` | **refused** — `https` keeps exact matching |

### `localhost` and `127.0.0.1` are not interchangeable

They are different hosts and each matches only itself. RFC 8252 §8.3 prefers
the literal address, because `localhost` resolves through a resolver an
attacker may be able to influence, but it does not forbid the name — and the
two clients this feature exists for disagree:

| Client | Registers |
| --- | --- |
| VS Code | `http://127.0.0.1/callback` |
| Claude Code | `http://localhost/callback` |

Register what your client actually uses. Registering both is legitimate when
a client varies, but it is a decision to take rather than one AXIAM takes for
you: treating one spelling as the other would silently widen every
registration to a host the operator did not write down.

### The token request is still exact

The authorization code stores the `redirect_uri` **as presented**, so the
token request's `redirect_uri` must repeat it exactly. A client that
authorized on port 51703 cannot redeem on 51704 — both would have been
accepted at `/oauth2/authorize`, and only one of them started this flow.

---

## Rate limiting

A token request carrying no client credential is counted in its own bucket,
keyed on **`client_id` and the transport peer address together**, with the
`token_per_min` allowance (`AXIAM__RATE_LIMIT__TOKEN_PER_MIN`, default 120 —
see the [deployment guide](../deployment/README.md)). It sits in front of the
endpoint's own rate limit rather than replacing it.

Neither half of that key works alone here. `client_id` on its own is a bucket
an unauthenticated caller mints by rotating a value they choose; the peer
address on its own puts every desktop client behind one NAT gateway — an
office, a household — into a single allowance. Deployments that front many
confidential clients from one egress IP should additionally set
`AXIAM__RATE_LIMIT__KEY=ip_client_id`, which applies the same reasoning to the
endpoint's main bucket.

---

## Worked example — a desktop client, end to end

```bash
# 1. Register (once, by an administrator)
curl -X POST "https://id.example.com/api/v1/oauth2-clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"vscode","redirect_uris":["http://127.0.0.1/callback"],
       "grant_types":["authorization_code","refresh_token"],
       "scopes":["openid","profile"],"token_endpoint_auth_method":"none"}'

# 2. The client starts, binds port 51703, and sends the user to:
#    https://id.example.com/oauth2/authorize
#      ?response_type=code
#      &client_id=oa_…
#      &redirect_uri=http://127.0.0.1:51703/callback
#      &scope=openid+profile
#      &code_challenge=<S256(verifier)>&code_challenge_method=S256
#      &state=<opaque>

# 3. The callback arrives on 51703; the client redeems the code with no secret
curl -X POST "https://id.example.com/oauth2/token?tenant_id=$TENANT_ID" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "redirect_uri=http://127.0.0.1:51703/callback" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$VERIFIER"
```

```jsonc
200 OK
{
  "access_token": "…",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "…",
  "scope": "openid profile"
}
```

Refreshing takes the same shape — `grant_type=refresh_token`,
`refresh_token=…`, `client_id=…`, and no secret.

---

## See also

* [FAPI 2.0 profile and mTLS client credentials](fapi2-profile.md) — the other
  end of the same registration field, and why `none` is refused there.
* [API documentation](../api/README.md) — the OpenAPI document, which carries
  `none` in the `token_endpoint_auth_method` enum.
* `crates/axiam-api-rest/tests/public_client_test.rs` — every rule on this
  page, asserted.
