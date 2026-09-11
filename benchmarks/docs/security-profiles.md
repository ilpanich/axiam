# Security Profiles

A core goal of this framework is to measure not just *how fast* a system is, but
*how fast it is at a given security posture* — and what stronger security costs.

We replay the identical workload across an ordered matrix of profiles, from the
weakest (plaintext) to the strictest (mutual-TLS with client-certificate
authentication and TLS 1.3-only). Each profile is a set of environment overrides
(`profiles/p*.env`) plus a registry entry (`profiles/profiles.yaml`) that the
orchestrator and report consume.

## The matrix

| ID            | Transport            | Min TLS | Cipher policy        | Client auth        | Intended use                              |
|---------------|----------------------|---------|----------------------|--------------------|-------------------------------------------|
| `p0-plaintext`| HTTP (no TLS)        | —       | —                    | none               | Baseline / behind a trusted mesh sidecar  |
| `p1-tls12`    | HTTPS                | 1.2     | default/broad        | none               | Legacy-compatible public endpoint         |
| `p2-tls13`    | HTTPS                | 1.3     | TLS 1.3 suites only  | none               | Modern recommended default                |
| `p3-mtls`     | HTTPS + mutual TLS   | 1.3     | TLS 1.3 suites only  | X.509 client cert  | Zero-trust / IoT device auth (AXIAM mTLS) |

`p0` is the speed ceiling (no crypto on the wire). Each higher tier adds cost; the
report quantifies that cost relative to `p0` (see
[`methodology.md`](methodology.md) §5 "Security cost").

## What each profile pins

Each `p*.env` exports a common, target-agnostic contract consumed by
`runner/run-benchmark.sh` and the target compose files:

```sh
BENCH_SCHEME           # http | https
BENCH_TLS_MIN          # "" | 1.2 | 1.3
BENCH_TLS_CIPHERS      # cipher allow-list (TLS1.2 profiles)
BENCH_CLIENT_CERT      # "" | path to client cert PEM (mTLS)
BENCH_CLIENT_KEY       # "" | path to client key  PEM (mTLS)
BENCH_CA_CERT          # path to CA bundle that signed the server cert
BENCH_VERIFY_TLS       # true|false (always true except p0)
```

k6 reads `BENCH_CLIENT_CERT/KEY` and `BENCH_CA_CERT` to present a client cert and
verify the server. TLS version/cipher *enforcement* happens on the **server** side,
configured per target:

* **AXIAM** — terminates TLS at the edge. For benchmarking we front the
  resource-capped `axiam-server` with the profile's TLS settings. Because AXIAM's
  k8s deployment typically terminates TLS at an ingress, the `p1`–`p3` profiles
  attach a minimal TLS terminator (see `targets/axiam/docker-compose.yml`) pinned
  to the profile's `BENCH_TLS_MIN`/ciphers, and for `p3` AXIAM's native
  certificate-based authentication (mTLS for IoT devices, per the design doc) is
  exercised directly.
* **Keycloak** — supports `https-protocols` and client-cert (`x509`) auth natively;
  the profile env maps onto Keycloak's own settings in its compose file.
* **Zitadel** — TLS mode set via `ZITADEL_TLS_*`.

## Certificate material

mTLS profiles need a CA, a server cert, and a client cert. Generate a throwaway
set once into `profiles/certs/` (gitignored):

```bash
just bench-certs   # wraps runner/gen-certs.sh
```

This produces:
```
profiles/certs/ca.crt        # test CA (also used as BENCH_CA_CERT)
profiles/certs/server.crt    # server cert (SAN: localhost)
profiles/certs/server.key
profiles/certs/client.crt    # client cert for p3-mtls
profiles/certs/client.key
```

> These are **test-only** certificates with short lifetimes. Never reuse them
> outside the benchmark sandbox. The directory is gitignored.

## Client IP and the rate limiters

`p1`–`p3` put an nginx edge in front of `axiam-server`; `p0` talks to the
server's own listener directly. That makes the TLS profiles a one-reverse-proxy
topology — the same one `docs/deployment/README.md` ships — and a proxy that
does not forward the client address makes every request look like it came from
the proxy.

Each edge conf therefore sets `X-Forwarded-For` (`$proxy_add_x_forwarded_for`),
and the target compose leaves `AXIAM__RATE_LIMIT__TRUSTED_HOPS` at its default
`0`, which is the value that topology calls for (`TRUSTED_HOPS` = proxies − 1 —
see [Deriving `TRUSTED_HOPS`](../../docs/deployment/README.md#deriving-trusted_hops)).
The two go together: with the header present and `TRUSTED_HOPS = 0` the server
keys on the real client address, exercising `XForwardedForKeyExtractor` exactly
as a production deployment does.

**This moves no measured number.** k6 drives every VU from a single host, so
there is one client address either way and a `rl=prod` pass still fills one
bucket — which is what `runner/rl_prod_check.py` compares against the configured
limit. What it changes is *which code path* is measured, and that matters
because the mismatched version of it is silent: the R-4 hardening logs a WARN
and increments `axiam_rate_limit_xff_discarded_total` only when a header is
present and discarded. A request carrying **no** `X-Forwarded-For` is
deliberately not counted (a client with no proxy in front of it is not a
misconfiguration), so the previous configuration collapsed the keying and said
nothing about it.

## Reading the security-cost output

The report prints, per (target, scenario), a small table:

```
profile        throughput   p95(ms)   Δ-throughput   Δ-p95(ms)
p0-plaintext      4,820        12.1       baseline      baseline
p2-tls13          4,610        13.4        -4.4%         +1.3
p3-mtls           4,180        16.9       -13.3%         +4.8
```

Interpretation: TLS 1.3 costs this target ~4% throughput and ~1.3 ms p95; adding
client-certificate auth costs ~13% throughput and ~4.8 ms p95. Comparing those
deltas *across targets* shows which implementation pays the smallest price for
strong security — often as important as the raw plaintext number.
