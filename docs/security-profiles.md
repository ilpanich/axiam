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

### ALPN / HTTP-version (`AXIAM__SERVER__TLS__HTTP2`, default `true`)

The rustls config is built advertising `h2` + `http/1.1` by default. Setting
`AXIAM__SERVER__TLS__HTTP2=false` narrows the config's ALPN list to
`http/1.1` only.

**Caveat — actix-web re-adds h2.** The REST listener is served through
actix-web's `HttpServer::bind_rustls_0_23`, whose service factory
(`actix_http::HttpService::rustls_0_23_with_config`) unconditionally
**prepends** `["h2", "http/1.1"]` to whatever ALPN we configure. As a result,
on the actix bind the `http2=false` knob is an *intent signal* — h2 is re-added
and still wins negotiation. A genuinely `http/1.1`-only TLS 1.3 listener is
obtained by fronting with the `tls13-h1` nginx edge
(`benchmarks/targets/axiam/tls/tls13-h1.conf`). The rustls-level list is still
authoritative for any non-actix consumer of the config and is unit-tested. See
`benchmarks/PRIVATE_BENCH_ANALYSIS.md` §4.3 for why this matters (the p2 TLS
throughput asymmetry is primarily an h2-vs-h1.1 effect).

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
| p2-tls13  | TLS 1.3 (h2 by default)      | yes (native overlay) | h1-isolation via `tls13-h1.conf` edge |
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
