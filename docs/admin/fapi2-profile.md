# FAPI 2.0 profile and mTLS client credentials

AXIAM can register an OAuth2 client under the **FAPI 2.0 Security Profile
(Final)** constraint bundle, authenticate clients with mutual TLS instead of a
shared secret, and issue **certificate-bound** access tokens that a stolen copy
cannot use.

All three are opt-in per client. **A deployment that changes nothing behaves
exactly as it did before.** Every field below defaults to what an AXIAM client
already was, and the tests that assert this are in
`crates/axiam-oauth2/src/fapi.rs` — the design's load-bearing property, not an
aspiration.

---

## The one switch

```jsonc
POST /api/v1/oauth2-clients
{
  "name": "payments-rp",
  "redirect_uris": ["https://rp.example/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid"],

  "profile": "fapi2",                                    // <- the switch
  "require_par": true,
  "token_endpoint_auth_method": "tls_client_auth",
  "tls_client_auth_san_dns": "payments-rp.example",
  "tls_client_certificate_bound_access_tokens": true
}
```

`profile: "fapi2"` is not a label. The server **refuses the registration**
unless it also carries `require_par`, a **strong** `token_endpoint_auth_method`,
and **some** sender-constraining — naming which one is missing:

```
400 a fapi2 client must set require_par: FAPI 2.0 §5.3.1.2 requires pushed
    authorization requests
```

That refusal is the point. A client satisfying eleven of twelve FAPI
constraints is not "mostly FAPI", it is a client with a hole — so the bundle
cannot be half-applied, and a reviewer can answer *"is this client
financial-grade?"* by reading one field.

Validation runs **before** the write on create, and against the **merged** row
on update. Flipping `profile` to `fapi2` on a client that has none of the rest
is a well-formed patch and a completely broken client; it is refused.

### What the switch turns on

| Constraint | Where it is enforced |
|---|---|
| PAR mandatory | `require_par` forced at registration; `/oauth2/authorize` refuses a direct request |
| PKCE mandatory, `S256` only | required of confidential clients too under this profile; `S256`-only is already global |
| Strong client authentication | registration requires an mTLS method **or** `private_key_jwt` |
| Sender-constrained tokens | registration requires certificate binding **or** DPoP |
| `response_type=code` only, no token in any URL | already global — no other response type exists in this server |
| Strict `redirect_uri` equality | already global — exact match, no prefixes, no wildcards |
| Authorization code single-use | already global, and guaranteed rather than intended: a guarded update inside a transaction plus a post-commit nonce read-back |
| EdDSA only, never `none` | already global — hard-coded at encode and decode |

Seven of those were already true for every AXIAM client. The profile adds the
first four and refuses to let the others be relaxed.

### Two onboarding paths, and how to choose

FAPI 2.0 asks two independent questions, and each has two acceptable answers.
**All four pairings are valid**; the profile does not require the two columns to
match.

| | mutual TLS | asymmetric JWT |
|---|---|---|
| **Client authentication** | `tls_client_auth`, `self_signed_tls_client_auth` | `private_key_jwt` |
| **Sender-constraining** | `tls_client_certificate_bound_access_tokens` | `dpop_bound_access_tokens` |

What the gate refuses is a client with strong authentication and
sender-constraining from **neither** — the shape a half-finished migration
produces.

**Choose mTLS when the client can reach an AXIAM mTLS listener directly.** It is
cheaper: possession is proved once by the TLS handshake and amortised over every
request on the connection, so binding costs one SHA-256 per token and nothing at
all per request. This is the IoT shape AXIAM is built for.

**Choose `private_key_jwt` + DPoP when it cannot.** A client behind a
TLS-terminating load balancer, an API gateway or a CDN cannot present a client
certificate to AXIAM — the connection AXIAM sees is the proxy's. Before this
path existed, such a client had no route to a FAPI registration here at all.

The cost is real and worth stating before you pick: **DPoP verifies an
asymmetric signature on every single request**, where mTLS binding verifies
none. If both are available to you, use mTLS.

---

## `private_key_jwt` client authentication (RFC 7523 §2.2)

The second client-authentication family. The client signs a short-lived JWT with
a private key whose public half AXIAM holds.

```jsonc
POST /api/v1/oauth2-clients
{
  "name": "payments-rp-behind-a-gateway",
  "redirect_uris": ["https://rp.example/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "scopes": ["openid"],

  "profile": "fapi2",
  "require_par": true,
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks_uri": "https://rp.example/.well-known/jwks.json",   // or "jwks": "{...}"
  "dpop_bound_access_tokens": true
}
```

### Where the keys come from — exactly one source

RFC 7591 §2 permits `jwks` **or** `jwks_uri`, never both. Registering both is
refused, and so is registering neither:

```
400 private_key_jwt requires exactly one of jwks or jwks_uri (RFC 7591 §2);
    2 were registered
```

Two key sources are two answers to "which keys authenticate this client", and
the union of them is a credential nobody registered.

| Source | Use it when | What it costs you |
|---|---|---|
| `jwks` (inline) | the client's keys change rarely, or you want no outbound fetch at all | rotation is an admin API call |
| `jwks_uri` | the client publishes and rotates its own keys | AXIAM fetches the URL |

**`jwks_uri` is fetched through the same guard a federated IdP's JWKS is.** That
means a 1-hour TTL, 24-hour stale-while-revalidate if the client's endpoint is
down, a 512 KiB body cap, and — this is the one that surprises people — the
**SSRF guard refuses private and loopback addresses**. A `jwks_uri` pointing at
`http://10.0.0.5/jwks.json` or `https://localhost/...` will never be fetched,
and the client will never authenticate. Use `jwks` for an internal client, or
publish the key set somewhere publicly resolvable.

The URL must also be absolute `https`. A plaintext URL is refused at
registration, because AXIAM fetches it to obtain the keys that authenticate this
client and a rewritable credential is not a credential.

### What the client sends

```http
POST /oauth2/token?tenant_id=...
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=oa_...
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=eyJhbGciOiJFZERTQSJ9...
```

The assertion must carry `iss` = `sub` = the `client_id`, an `aud` naming this
server (either the issuer or the token-endpoint URL — both are accepted, because
OIDC Core §9 and RFC 7523 §3 disagree about which and refusing either would be
an interop failure with no security content), a future `exp` no more than an
hour out, and a **unique `jti`**.

### The rules that will bite you first

1. **`alg` comes from the registered key, not from the assertion header.** A
   header naming an algorithm the registered key does not use is refused, not
   reinterpreted. Permitted: `PS256`, `ES256`, `EdDSA`. **`RS256` is refused** —
   the profile excludes PKCS#1 v1.5 padding, and this is the single most common
   surprise when onboarding a client that worked against another server.
2. **A P-384 or P-521 key is refused.** Perfectly good keys, not on the
   profile's list.
3. **`jti` is single-use, permanently.** Not "within a window" — a `jti` that
   has authenticated once never authenticates again. A client that reuses one
   (some test harnesses do) will authenticate exactly once.
4. **A `kid` in the header selects, it does not hint.** If the assertion names a
   `kid`, only the key carrying it is tried.

### Rotation

Publish both keys in the `jwks`/`jwks_uri` during the overlap window; any
registered key may sign. This is the one place `jwks_uri` is genuinely easier
than inline: the client rotates without an admin API call.

---

## DPoP sender-constrained tokens (RFC 9449)

The second sender-constraining mechanism, for clients that cannot present a
certificate. Set `dpop_bound_access_tokens: true` and the client's tokens carry:

```json
"cnf": { "jkt": "<base64url-unpadded RFC 7638 thumbprint of the client's public key>" }
```

The token response says `"token_type": "DPoP"`, and the client must then send
**both** the token and a freshly signed proof on every request:

```http
GET /api/v1/whoami
Authorization: DPoP eyJhbGciOiJFZERTQSJ9...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6...
```

### What an operator needs to know

- **Ordinary clients are untouched.** A client without
  `dpop_bound_access_tokens` still gets `"token_type": "Bearer"` and is never
  asked for a proof. Turning DPoP on for one client changes nothing for any
  other.
- **Proofs are bound to the method and URI.** A proof minted for
  `POST /oauth2/token` cannot be used on `GET /api/v1/whoami`. The comparison
  strips query and fragment and normalises nothing else.
- **Proofs are fresh for 60 seconds, in both directions**, and single-use within
  that window at the token endpoint. A client with a badly skewed clock will
  fail every request; this is the first thing to check.
- **`dpop_require_nonce`** makes the first request of each window a challenge:
  AXIAM answers `400 use_dpop_nonce` with a `DPoP-Nonce` header, and the client
  retries with that value in the proof. It costs a round trip, so it is `false`
  by default. Turn it on when you want proofs to be unusable before the server
  has spoken.
- **Both constraints at once is a conjunction.** A client registered with both
  `tls_client_certificate_bound_access_tokens` and `dpop_bound_access_tokens`
  gets a `cnf` carrying both, and a resource server must satisfy **both**.

### What DPoP costs, honestly

DPoP verifies an **asymmetric signature on every request**. Certificate binding
verifies none — the handshake did it once for the whole connection. These are
different cost classes, not different constants.

`bench_dpop_binding` in `crates/axiam-auth/benches/auth_bench.rs` measures the
pieces, and `claude_dev/extra-B-track-features.md` §X5.1 publishes what has
actually been measured — deliberately without a percentage, for the same reason
the certificate-binding "~1%" headline was withdrawn. **If both mechanisms are
open to you, mTLS is the cheaper one.**

---

## mTLS client authentication (RFC 8705 §2)

Two methods. **The registration decides which credential authenticates, never
the request** — so a client registered for mTLS is authenticated by its
certificate even if it also posts a secret, and the two can never become an OR
that an attacker holding either could satisfy.

### `tls_client_auth` — a CA issued the certificate

Register **exactly one** expected identity (RFC 8705 §2.1.2 permits one; two are
refused rather than OR-ed):

| Field | Matched against |
|---|---|
| `tls_client_auth_subject_dn` | the certificate's subject DN, RFC 4514 string form, **exact** |
| `tls_client_auth_san_dns` | a `dNSName` SAN, case-insensitive (RFC 4343) |
| `tls_client_auth_san_uri` | a `uniformResourceIdentifier` SAN, exact |

Get the DN with the same tool the comparison assumes:

```bash
openssl x509 -in client.crt -noout -subject -nameopt rfc2253
```

The DN comparison is **exact** — no case folding, no attribute reordering, no
whitespace normalisation inside values. That is deliberate: normalising DN
comparison is where DN-matching CVEs live, and an exact match can only ever be
too *strict*, which fails an onboarding rather than authenticating a stranger.
Surrounding whitespace on the registered value is trimmed, because a DN pasted
from a terminal routinely carries a leading space and no two certificates differ
only by outer whitespace.

**Wildcards are not supported and never will be.** A `*.example.com` registered
here would authenticate every certificate that CA ever issued under that suffix
*as this client* — an authorization decision nobody should be able to make by
typing one character.

The deployment's mTLS listener must trust the issuing CA
(`AXIAM__SERVER__TLS__CLIENT_CA_PATH`). If it does not, the handshake fails
before AXIAM sees a request, so AXIAM's log shows nothing at all — check the
listener first when a client "cannot connect".

### `self_signed_tls_client_auth` — the certificate is the credential

Register the certificate's **`x5t#S256` thumbprint**: base64url, unpadded,
SHA-256 over the DER encoding.

```bash
openssl x509 -in client.crt -outform der \
  | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
```

A well-formed value is exactly 43 characters. A padded value, standard base64
(`+`/`/`), or a hex digest is rejected **at registration** rather than silently
never matching — that typo is worth hearing about during onboarding, not six
weeks later as an unexplained `invalid_client`.

`self_signed_tls_client_auth_thumbprints` is a **list** so a rotation can
overlap: register the new thumbprint, roll the client, then remove the old one.

> RFC 8705 §2.2 registers self-signed certificates inside the client's
> `jwks`/`jwks_uri`. AXIAM registers the thumbprint instead — the comparison
> reduces to an equality check against a registered key either way, and a
> thumbprint is that check with no JWKS parser on the authentication path. The
> cost: you cannot rotate by having the client republish a `jwks_uri`; the new
> thumbprint must be registered.

### Every failure looks the same

`invalid_client`, with one uniform description, whatever went wrong — no
certificate presented, wrong certificate, client registered nothing. An
unauthenticated caller must not be able to learn any of those about a client id
they have not authenticated as.

**The specific reason is in the server log**, at `debug` for the ordinary cases
and `warn`/`error` for registrations that cannot work. That is where to look
when onboarding fails.

Note that the `X-Client-Certificate` proxy header — which the IoT device-auth
path accepts when TLS terminates upstream — is **not** accepted here, and there
is no setting that enables it. A client credential must not be assertable by
anything that can set a header.

---

## Certificate-bound access tokens (RFC 8705 §3)

Set `tls_client_certificate_bound_access_tokens: true` and tokens issued to that
client carry:

```json
"cnf": { "x5t#S256": "<thumbprint of the certificate presented at the token endpoint>" }
```

This is **independent of the authentication method** — a client may authenticate
with a secret over an mTLS connection and still get bound tokens. The FAPI
profile forces it on; it is not the only thing that can.

Three behaviours worth knowing:

- **A client that requires binding and presents no certificate is refused**, not
  quietly given an unbound token. Silently downgrading would hand a bearer token
  to exactly the one request that arrived without a certificate.
- **Refresh re-derives the binding** from the certificate on *that* connection.
  It is never carried forward from the token being refreshed — otherwise a
  client that lost its certificate could keep renewing tokens bound to it, and a
  rotation performed to revoke access would not.
- **Token exchange (RFC 8693) does not inherit or invent a constraint.** The
  exchanging client is a different party from the subject.

### Your resource servers must actually check it

Issuing `cnf` buys **nothing** if resource servers ignore it. The claim is
exposed two ways:

- in the signed JWT, for local validation; and
- in the `POST /oauth2/introspect` response (RFC 8705 §3.3), for resource
  servers that introspect.

SDK contract §10.1 rule 9 (contract 1.15) makes the check mandatory in all
eleven SDKs. If you guard with hand-written middleware, implement this table:

| Token's `cnf` | Certificate on this connection | Do |
|---|---|---|
| absent | anything | **accept** |
| `x5t#S256` matching | that certificate | **accept** |
| `x5t#S256` not matching, or no certificate | — | **reject** |
| present, but no `x5t#S256` | anything | **reject** |

The last row is the one people get wrong. A `cnf` naming a method your validator
does not implement is an *unverifiable constraint*, not *no constraint* — read
the other way, a sender-constrained token silently becomes a bearer token the
day a newer server issues something your validator predates.

### What it costs

Measured (`cargo bench -p axiam-auth`, `bench_certificate_binding`):

| | |
|---|---:|
| extra work per bound token, at the mint | **~4.0 µs** |
| resource-server verification | **~0.07 µs** |

No per-request asymmetric cryptography: the certificate was verified once during
the TLS handshake, and issuance adds one SHA-256 plus about sixty bytes inside
the signature.

The **end-to-end** request-level cost has not been measured. Earlier planning
documents quoted "~1%"; that figure was a prediction, not a measurement, and it
is withdrawn until `benchmarks/`'s `bench-quick` has been run. Quote the
microsecond figures above, which are real — and note that they are criterion
micro-benchmarks of the mint in isolation, not a fraction of a request.

---

## Sender-constrained tokens on the gRPC surface

AXIAM's gRPC surface is the low-latency check plane for a service mesh, and it
is a resource server for AXIAM's own tokens — so it owes the same obligation the
REST surface does.

**Introspection carries the confirmation.** `TokenService.IntrospectToken` and
`ValidateToken` return `cnf` (with `x5t_s256` / `jkt`) and `token_type`, and
introspection additionally returns `scope`, `client_id`, `permissions` (a UMA
RPT's) and `ext_exchange_iss` (X4 cross-domain provenance). Until this landed,
gRPC introspection answered `active: true` for a bound token with **no way to
tell it was bound** — so a mesh resource server had no choice but to treat it as
a bearer token.

`valid: true` means the signature, expiry and tenant check out. It does **not**
mean the token may be used by whoever presented it: when `cnf` is present the
caller must prove possession against **its own** connection. AXIAM cannot do
that for them, because the proof is against the caller's connection and not the
one carrying the introspection call.

**AXIAM's own gRPC API enforces binding on inbound calls.** A certificate-bound
token is checked against the peer chain rustls verified for that connection.

**A DPoP-bound token is refused on gRPC, deliberately.** RFC 9449 binds a proof
to an HTTP method and URI (`htm`/`htu`), and a tonic interceptor runs before the
RPC path is bound to a request — it sees neither. Verifying a proof without them
would accept one captured from any other endpoint, which is worse than not
verifying at all, so the answer is the one rule 9 prescribes: **reject when you
cannot verify.**

The practical consequence for an operator: if you issue DPoP-bound tokens and
your services authorize through the mesh, terminate those tokens at the REST
surface, which has the method and URI. Certificate-bound tokens work on both.

---

## RFC 9207 `iss` — on by default, for everybody

Every authorization response now carries an `iss` parameter naming the issuer,
on success **and on error**, for every client whatever its profile. Discovery
advertises `authorization_response_iss_parameter_supported: true`.

Nothing to configure. It defends against the **mix-up attack**, where a response
minted by one authorization server is delivered to a client that thinks it came
from another. It is unconditional because mix-up is precisely the attack a
client does not know it is under, and it is on the error redirect because one
variant of the attack works by injecting an error response.

**Your clients have to check it.** A client that ignores the parameter gains
nothing. If you talk to more than one issuer, compare `iss` against the one you
started the flow with, on both the success and the error callback.

---

## Not implemented

`private_key_jwt` and DPoP used to be listed here. Both landed on 2026-08-14 and
have their own sections above. What remains out of scope:

- **FAPI Message Signing** (JARM, signed request objects, signed introspection
  responses). A separate optional OIDF certification; `response_mode=jwt` is not
  accepted.
- **Certificate-bound or DPoP-bound *refresh* tokens.** Only access tokens carry
  `cnf`.
- **Sender-constrained token exchange.** An RFC 8693 exchange deliberately does
  not inherit or mint a `cnf`: the exchanging client is a different party from
  the subject, so copying the constraint would bind the new token to a key its
  holder does not have.
- **A stored, rotating DPoP nonce.** `dpop_require_nonce` issues a fresh nonce
  with each challenge; AXIAM does not currently keep a per-client nonce to
  compare a later proof against.

---

## See also

- [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) — running the OIDF conformance suite
- [`docs/security-profiles.md`](../security-profiles.md) — the TLS/mTLS listener profiles
- [`docs/pki/README.md`](../pki/README.md) — issuing certificates from an AXIAM organization CA
- `sdks/CONTRACT.md` §10.1 rule 9 and §21 — the relying-party obligations
