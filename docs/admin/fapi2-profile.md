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
unless it also carries `require_par`, an mTLS `token_endpoint_auth_method`, and
`tls_client_certificate_bound_access_tokens`, naming which one is missing:

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
| Strong client authentication | registration requires an mTLS method |
| Sender-constrained tokens | registration requires certificate binding |
| `response_type=code` only, no token in any URL | already global — no other response type exists in this server |
| Strict `redirect_uri` equality | already global — exact match, no prefixes, no wildcards |
| Authorization code single-use | already global, and guaranteed rather than intended: a guarded update inside a transaction plus a post-commit nonce read-back |
| EdDSA only, never `none` | already global — hard-coded at encode and decode |

Seven of those were already true for every AXIAM client. The profile adds the
first four and refuses to let the others be relaxed.

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
microsecond figures above, which are real.

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

- **`private_key_jwt`** (RFC 7523) client authentication. FAPI 2.0 accepts it or
  mTLS; AXIAM implements mTLS. This matters for certification scope — see
  [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md).
- **DPoP** (RFC 9449). FAPI 2.0 accepts it or mTLS certificate binding; AXIAM
  implements the latter. A client that cannot do mTLS has no route to a
  sender-constrained token here.

---

## See also

- [`claude_dev/fapi-conformance-runbook.md`](../../claude_dev/fapi-conformance-runbook.md) — running the OIDF conformance suite
- [`docs/security-profiles.md`](../security-profiles.md) — the TLS/mTLS listener profiles
- [`docs/pki/README.md`](../pki/README.md) — issuing certificates from an AXIAM organization CA
- `sdks/CONTRACT.md` §10.1 rule 9 and §21 — the relying-party obligations
