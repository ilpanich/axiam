# AXIAM TLS & Security Profiles

This document records the security-relevant decisions for AXIAM's native
in-process TLS listener (`crates/axiam-server/src/tls.rs`), and how the
benchmark TLS profiles (p0–p3) map onto them.

TLS termination at a proxy/load balancer remains the **recommended default**
(the server binds plaintext unless `server.tls.enabled` is set); the native
listener is an opt-in alternative (ASVS V9.1.2/V9.1.3, D-06).

## Native TLS listener

When `AXIAM__SERVER__TLS__ENABLED=true`, the server builds a rustls
`ServerConfig`:

- **TLS 1.3 only** (`rustls::version::TLS13`). TLS 1.2 and earlier are not
  offered natively — every TLS 1.3 cipher suite is ASVS-approved, so no manual
  cipher filtering is needed (V9.1.3). Legacy TLS 1.2 clients must use an edge
  proxy; native AXIAM is **TLS 1.3-only by policy** (see p1 below).
- **Client-certificate / mTLS verification is native (D3).** See
  [Native client-certificate auth](#native-client-certificate-auth-mtls) below.
  Default is server-auth only (`with_no_client_auth`), backward compatible.
- **`ring` crypto provider**, selected explicitly for determinism.

### Native client-certificate auth (mTLS)

Client-certificate authentication is terminated **in-process** — no nginx edge
and, critically, **no proxy-header identity assertion** (`X-Client-Certificate`
et al.) in the trusted path. Two new config keys control it:

| Env var | Values | Default | Meaning |
|---------|--------|---------|---------|
| `AXIAM__SERVER__TLS__CLIENT_AUTH` | `off` \| `optional` \| `required` | `off` | client-cert policy |
| `AXIAM__SERVER__TLS__CLIENT_CA_PATH` | PEM bundle path | — | trust anchors for client certs |
| `AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH` | path | beside `CERT_PATH` | where the bundle built from CAs flagged `mtls_trust_anchor` is written |

- **`off`** — server-auth only (unchanged behaviour; the config is built with
  `with_no_client_auth()`).
- **`optional`** — a client certificate is requested and, if presented,
  **verified** against the CA bundle, but anonymous clients are still accepted
  (`WebPkiClientVerifier::builder(..).allow_unauthenticated().build()`).
- **`required`** — the TLS handshake is **rejected** unless the client presents
  a certificate that verifies against the CA bundle
  (`WebPkiClientVerifier::builder(..).build()`).

The verifier is a `rustls::server::WebPkiClientVerifier` (rustls 0.23) built from
a `RootCertStore` loaded from `CLIENT_CA_PATH`, using the same explicit `ring`
provider as the server config. Startup **fails fast** (an `io::Error` aborting
the process) when client-auth is enabled but the CA path is unset,
missing/unreadable, empty, or malformed — a misconfigured mTLS server never
starts serving.

**Identity comes from the verified certificate, not a header.** When a client
cert verifies during the handshake, the server's `HttpServer::on_connect` hook
lifts the rustls-verified leaf certificate (via the connection's
`peer_certificates()`) into the per-connection extensions as a
`VerifiedClientCert` (DER + parsed SAN + SPKI SHA-256). Certificate-auth
handlers read it back with `HttpRequest::conn_data::<VerifiedClientCert>()` and
feed the **verified DER** into `DeviceAuthService::authenticate_der`. The legacy
`X-Client-Certificate` proxy header is consulted **only** as a fallback when no
verified peer certificate is present on the connection (i.e. TLS was terminated
upstream) — so with native mTLS enabled a spoofed header can never assert an
identity.

### ALPN / HTTP version — the listener is always `h2` + `http/1.1`

The native TLS listener advertises `h2` then `http/1.1`, and **this is not
configurable**.

`AXIAM__SERVER__TLS__HTTP2=false` used to narrow the rustls config's ALPN list,
log a warning, and then serve h2 anyway. **It now aborts startup** with an
`Unsupported` error. A setting that silently does the opposite of what it says
is worse than no setting — especially in a benchmark, where it can manufacture a
fake "HTTP/1.1 cell".

Why it cannot work (verified against actix-web 4.14.0 / actix-http 3.13.1 /
rustls 0.23.42, the versions in `Cargo.lock`):

- `HttpServer::bind_rustls_0_23` (actix-web `src/server.rs:587`) routes through
  `actix_http::HttpService::rustls_0_23_with_config` (actix-http
  `src/service.rs:735`), which unconditionally **prepends** `["h2",
  "http/1.1"]` to whatever ALPN list we configure (`src/service.rs:747-749`) —
  our list is appended, so `h2` is always first.
- rustls selects ALPN by **server preference order**
  (rustls `src/server/hs.rs:99-108`), so the prepended `h2` wins for every
  client that offers it. Appending can never outrank it.
- h2 cannot be compiled out either: actix-web's `rustls-0_23` feature implies
  `http2`, and the prepend is gated on `rustls-0_23` alone.

**To serve TLS 1.3 without HTTP/2**, leave `server.tls` disabled and terminate
TLS at an edge that does not enable HTTP/2 — e.g.
`benchmarks/targets/axiam/tls/tls13-h1.conf`. There is no in-process option
short of replacing `HttpServer` with a hand-built `H1Service` listener, which
AXIAM deliberately does not do.

### HTTP/2 tuning (`AXIAM__SERVER__H2__*`)

Two HTTP/2 flow-control settings are exposed. Both are **unset by default**, and
unset means the corresponding actix setter is never called — a default
deployment behaves exactly as it did before these keys existed.

| Env var | Type | Unset ⇒ actix default |
|---------|------|-----------------------|
| `AXIAM__SERVER__H2__INITIAL_STREAM_WINDOW_SIZE` | bytes (`u32`) | 1 MiB |
| `AXIAM__SERVER__H2__INITIAL_CONNECTION_WINDOW_SIZE` | bytes (`u32`) | 2 MiB |

Values outside `1 … 2147483647` (RFC 9113 §6.5.2) are rejected at startup rather
than panicking inside a worker at the first handshake. These only affect the TLS
bind — the plaintext bind is HTTP/1.1.

`max_concurrent_streams` is **not** exposed, because actix-http 3.13.1 provides
no way to set it: its h2 handshake builder configures only the two windows
(`src/h2/mod.rs:60-71`), and neither `HttpServiceBuilder` nor `HttpServer`
surfaces the underlying `h2::server::Builder::max_concurrent_streams`. AXIAM
therefore never sends `SETTINGS_MAX_CONCURRENT_STREAMS`, i.e. it advertises no
stream limit. Keep-alive is not exposed here either: it is shared by HTTP/1.1
and HTTP/2 and is not an HTTP/2-specific lever.

### Operational note — one HTTP/2 connection is served by one core

actix pins each accepted TCP connection to a single worker thread
(actix-server `src/accept.rs:432-438`) and spawns every HTTP/2 stream onto that
worker's single-threaded runtime (actix-http `src/h2/dispatcher.rs:134-135`;
`actix_rt::spawn` is `tokio::task::spawn_local`). HTTP/2 multiplexing therefore
buys header compression and ordering, **not** parallelism: all streams of *one*
connection share one core.

Consequences for high-volume callers:

- A single client process holding **one** pooled HTTP/2 connection cannot
  saturate a multi-core AXIAM instance, no matter how many concurrent requests
  it multiplexes.
- Spread high-volume token traffic across **several connections** (client-side
  pooling, or a stream cap per connection) and across **replicas**. Adding CPUs
  to one replica only helps when the number of inbound connections is at least
  the number of workers.
- AXIAM cannot induce this from the server side: with no advertised
  `SETTINGS_MAX_CONCURRENT_STREAMS`, a client is never obliged to open a second
  connection.

**How much this actually costs you depends entirely on your client's connection
count, and most clients are fine.** The paragraph above is a real property of
the listener, but it only bites a caller that funnels all of its concurrency
through one connection. Measured (H6, 2026-07-29, `server:1.0.0-alpha19`,
2 CPU / 2 actix workers, TLS 1.3 + h2 on the native listener): a load generator
running 10 / 50 / 100 concurrent clients opened **10 / 50 / 100** TCP
connections, and the two `actix-server wo` threads stayed within ~5% of each
other's CPU at every level — i.e. no affinity imbalance occurred at all, and the
h2 penalty on throughput was **0%** relative to the same load over HTTP/1.1 on
the same TLS endpoint. Treat this section as *sizing guidance for a
single-connection caller*, not as a general HTTP/2 tax.

TLS crypto cost is separately small and is not a handshake cost: with session
resumption working (`http_req_tls_handshaking ≈ 0`), TLS 1.3 termination in
process costs roughly **10-15% of throughput on a trivially cheap endpoint**
(JWKS: −12.8% measured on the H6 host, −12.5% on the earlier benchmark host —
two different machines agreeing) and proportionally less as the endpoint does
more work per request (userinfo −3.7%, introspection −0.2%). A *larger* p2
penalty than that on any single endpoint is evidence about that endpoint, not
about TLS.

Full evidence and the closing of the "does TLS/HTTP2 halve token issuance?"
question:
[`claude_dev/b2-tls-h2-investigation.md`](../claude_dev/b2-tls-h2-investigation.md)
(reproduce with `benchmarks/run-improvement-tasks.sh h6-tls-proto`).

### Session resumption

The native config enables **TLS 1.3 ticket-based (PSK) session resumption**:
a `rustls::crypto::ring::Ticketer` is installed plus a bounded in-process
`ServerSessionMemoryCache`. Without these, rustls performs a full ECDHE
handshake on **every** connection — a per-request fixed cost that inflated p2
token-endpoint latency in the 2026-07-19 benchmark. Resumption lets repeat
connections from the same client resume instead.

### 0-RTT / early data — **explicitly disabled** (decision)

TLS 1.3 **0-RTT / early-data is deliberately NOT enabled.** rustls'
`ServerConfig::max_early_data_size` is left at its default of `0`, so the
server accepts no early data.

Rationale: early data is **replayable** by a network attacker. The endpoints
that dominate the TLS traffic — `/oauth2/token` (authorization_code, refresh,
client_credentials), `/introspect`, `/revoke` — are **non-idempotent POSTs**.
Replaying a refresh-token grant or a revocation as 0-RTT early data is an
unacceptable correctness/security risk (token reuse, rotation races). The
modest handshake latency saved by 0-RTT does not justify it for an IAM. If a
future read-only, idempotent, safely-replayable endpoint ever wants 0-RTT, it
must be gated separately and never on the token endpoints.

This decision is enforced by omission (we never raise `max_early_data_size`)
and recorded here so it is not "optimized in" later without review.

### TCP_NODELAY

actix-server enables `TCP_NODELAY` on accepted sockets by default, and the
plaintext and rustls binds share the **same** `HttpServer` builder (only the
bind method differs), so Nagle behaviour is identical across p0 and p2. No
override is applied.

## Benchmark profile mapping

| Profile   | Transport                    | Native AXIAM? | Notes |
|-----------|------------------------------|---------------|-------|
| p0        | plaintext HTTP/1.1           | yes           | baseline |
| p1-tls12  | TLS 1.2                      | **no — N/A-by-policy** | AXIAM is **TLS 1.3-only natively** (per the security standards; ASVS V9.1.2). TLS 1.2 is never offered in-process; a legacy TLS 1.2 endpoint, if ever needed, is an nginx-edge concern outside AXIAM. This profile stays nginx-fronted when run. |
| p2-tls13  | TLS 1.3 (always h2 when the client offers it) | yes (native overlay) | h1-isolation is only obtainable via the `tls13-h1.conf` edge — the native listener cannot be made h1-only (see ALPN above). That edge and `tls13.conf` are a matched pair differing only in `http2 on;`, so they are the only controlled h1-vs-h2 comparison in the harness |
| p3-mtls   | TLS 1.3 + client cert        | **yes (native overlay, D3)** | native mTLS: `docker-compose.native-mtls.yml` sets `CLIENT_AUTH=required` + `CLIENT_CA_PATH=/certs/ca.crt`; no nginx edge. Identity from the verified cert, not a header. |

### Why p1-tls12 is N/A-by-policy (not "not yet implemented")

TLS 1.2 support is a **deliberate non-goal** for the native listener, not a
missing feature. AXIAM's security standards mandate **TLS 1.3 minimum for all
external communication**, and restricting to TLS 1.3 is also what lets the
native config skip manual cipher-suite filtering (every TLS 1.3 suite is
ASVS-approved, V9.1.3). Adding TLS 1.2 would regress that posture. Deployments
that must terminate legacy TLS 1.2 for old clients do so at an edge proxy, which
is that proxy's policy surface — AXIAM itself never negotiates below TLS 1.3.
The p1-tls12 benchmark profile therefore stays nginx-fronted; there is no native
overlay for it by design.

## Session-revocation posture: REST vs gRPC (A4/J10)

Local token verification proves a token was issued and has not expired. It
cannot prove the session behind it still exists — that requires re-checking
server state per request, and the two AXIAM transports make different choices
about whether to pay for it.

| | REST | gRPC (default) | gRPC (`strict`) |
|---|---|---|---|
| Token signature + expiry | ✅ | ✅ | ✅ |
| Session revoked since issue? | ✅ per request | ❌ **not checked** | ✅ per request |
| Revocation takes effect after | immediately (or session-cache TTL) | **token expiry — up to 15 min** | immediately (or session-cache TTL) |

### The default, stated plainly

**By default, a user who logs out keeps passing gRPC authorization until their
access token expires — up to 15 minutes.** That is a deliberate trade: gRPC is
the low-latency service-mesh check surface, and not paying a session read per
request is a meaningful part of why it measures where it does.

It is written here because a trade nobody wrote down is indistinguishable from
a bug. This is not a property an operator should discover from a benchmark
analysis.

### Enabling strict mode

```bash
AXIAM__GRPC__STRICT_REVOCATION=true
```

Every gRPC request then re-checks session validity, matching REST.

**Enable the session-validation cache alongside it**, or you are choosing one
datastore read per gRPC request:

```bash
AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS=5
```

With the cache on, the hot path costs a hash lookup and only a miss costs a
read. The cache instance is shared with REST, so every REST-side invalidation
hook — logout, password change, MFA reset, refresh rotation — already serves
gRPC: **event-path revocation is immediate in strict mode**, and the TTL bounds
only revocations that happened out of band (on another replica, or directly in
the datastore). Run 5 measured the event path at 262 ms.

Expect the gRPC check profile to approach REST's revocation-checked one. The
labelled bench cell for strict-mode overhead is a run-6 deliverable; until it
exists, treat "approaches REST's profile" as a prediction rather than a
measurement.

### Which one you want

- **Service mesh, short-lived tokens, revocation handled by token lifetime** →
  default. Shorten `AXIAM__AUTH__ACCESS_TOKEN_LIFETIME_SECS` if 15 minutes is
  too long a window; that is the knob that bounds the default posture.
- **gRPC reachable by end-user sessions, or a compliance requirement that
  sign-out is immediate** → strict, with the session cache on.

### Token exchange inherits this posture (SEC-091)

`POST /oauth2/token` with `grant_type=…:token-exchange` does not consult
session revocation either — it validates the subject token's signature,
issuer, audience and expiry only, the same as the default (non-strict) posture
above. A logged-out-but-unexpired access token can therefore still be
exchanged. Two bounds, both enforced in code, keep this within the existing
posture rather than widening it: the exchanged token's lifetime can never
exceed the subject token's own remaining lifetime, and its granted privilege
is always a subset of the intersection of the subject's and the client's
scopes. See
[Revocation is not consulted at exchange time](api/token-exchange.md#revocation-is-not-consulted-at-exchange-time-sec-091)
for the full write-up.

## DPoP nonces are NOT implemented (SEC-097)

`OAuth2Client.dpop_require_nonce` exists on the model, in the SurrealDB schema,
in the admin create/update DTOs and in `sdks/openapi.json`. **Nothing reads
it.** The token endpoint passes `require_nonce: false` unconditionally, and the
comment that used to sit beside it claimed the opposite.

`axiam_oauth2::dpop::verify_dpop_proof` implements RFC 9449 §8 completely — the
mechanism exists and is simply never engaged. The reason it is not engaged is
that this deployment stores no per-client nonce to compare an echoed one
against: a challenge without server-side state (or a keyed, time-bounded MAC in
its place) would prove that the client is live and nothing else. Shipping that
as though it were a control is worse than shipping no control.

**What the API does now.** `POST`/`PUT /api/v1/oauth2-clients` refuse
`dpop_require_nonce: true` with `400`, naming the reason. `false` — the default,
and the value every stored row holds — is accepted unchanged, so the wire shape
is stable for the seven SDKs and no existing client is affected. The refusal is
the check a future nonce implementation deletes.

**What actually makes a DPoP proof unreplayable here**, and it is the stronger
of the two controls, is the single-use `jti`: every proof presented at
`/oauth2/token` is recorded through the same `UNIQUE`-index guard the
`private_key_jwt` client assertion uses, and a proof whose `jti` cannot be
recorded is refused rather than accepted. That is not optional and not
per-client. FAPI 2.0 does not mandate DPoP nonces.

**Known residual**, unchanged by this: the resource-server path in
`axiam-api-rest`'s extractor is synchronous and does not record `jti`, so
within the 60-second freshness window a proof for that exact method, URI and
access token could be presented twice there. Documented in the extractor and in
contract §21.7.2.

## Outbound SSRF guard — the operator override (SEC-107)

Every outbound fetch to an admin- or IdP-supplied URL (webhook delivery,
`jwks_uri`, OIDC discovery, the IdP token endpoint, SAML metadata, the FIDO MDS3
BLOB) goes through `axiam_pki::ssrf`, which resolves the host fresh, refuses the
fetch if **any** resolved address is non-globally-routable, and pins the exact
validated address into the connection so the socket that opens is the one that
was validated.

That rule is a *network-topology* control being used as a *trust* control, and
the two diverge in real deployments: a Kubernetes-internal Keycloak or Entra
proxy at `10.x` is a perfectly legitimate IdP, as is an internal webhook
consumer, an internal MDS mirror, or an air-gapped deployment where everything
is RFC1918. With no exception at all, the operator's only recourse is to run
AXIAM outside the guard's assumptions or to patch the binary — and a guard that
gets patched around protects nobody.

**`AXIAM__PKI__SSRF_ALLOWED_HOSTS`** is that exception: a comma-separated list
of host names (or literal IPs), matched **exactly**.

```
AXIAM__PKI__SSRF_ALLOWED_HOSTS=keycloak.internal,idp.corp.example
```

Five properties make it an exception rather than a hole, and none of them is
optional:

1. **Default-empty.** Unset — which is what every deployment gets unless
   somebody decides otherwise — means the address rule admits no exceptions at
   all. Startup logs which it is, either way.
2. **Set once, at startup.** It is installed in `main` from the environment and
   cannot be re-armed at runtime.
3. **Exact match only.** ASCII-lowercased equality. No wildcards, no suffix
   matching, no CIDRs. A CIDR exception can be widened by a DNS answer — allow
   `10.0.0.0/8` and *any* hostname an admin can set reaches everything in it. A
   host exception cannot: the operator names the exact destination.
4. **First hop only.** Redirect targets are always validated strictly. A
   `Location` header is attacker-influenced response data, not the URL the
   operator chose to trust.
5. **Cloud metadata endpoints stay unreachable**, even for an allowlisted host:
   `169.254.0.0/16`, `fe80::/10`, `fd00:ec2::254`, `100.100.100.200`,
   `192.0.0.192`, and the deprecated `::/96` encoding of any of them. An
   operator asking for their `10.x` IdP is not asking for `169.254.169.254`,
   and an allowlisted name whose DNS has been poisoned onto a metadata endpoint
   is exactly the attack this would otherwise re-open. The IPv4-mapped IPv6
   spelling (SEC-094) is canonicalised before this check, not after.

Every use of the exception is logged at `WARN` with the host and the address it
resolved to; an allowlisted host that resolves to a metadata endpoint is logged
at `ERROR` and refused.

**There is deliberately no `AXIAM__PKI__SSRF_ALLOW_PRIVATE=true`.** That is the
`verify_peer: false` of this module: it appears in a dev compose file, works,
and travels unchanged into production. `axiam-amqp`'s TLS config already carries
the long-form argument for why such a switch should not exist.
