# The backend on the public internet, terminating its own TLS

**Status:** design, written before the implementation and updated as it landed.
**Scope:** branch `claude/axiam-public-backend-tls`.
**Baseline:** `1.0.0-beta07`, commit `1c457f6` (the merge of the "Sign in with X"
login-provider work, which this assumes).

This document argues the change that moves AXIAM's *documented* deployment from
"one nginx serves the SPA and proxies the API" to "an edge routes by path, the
SPA is served at `/`, and the backend answers `/api` on the same origin over a
TLS connection it terminates itself."

Everything normative that comes out of it lands in
[`docs/deployment/README.md`](../docs/deployment/README.md),
[`docs/deployment/vault.md`](../docs/deployment/vault.md) and
[`claude_dev/threat-model-stride.md`](threat-model-stride.md). This file is where
the choices are argued, including the ones that were rejected.

Its companion is [`claude_dev/rpi5-prod-google-federation-guide.md`](rpi5-prod-google-federation-guide.md),
the operator runbook for the reference deployment.

---

## 1. Why the old topology had to change

The deployment `docker/nginx.conf` and the Pi guide described was:

```
client ──443/TLS──> Caddy ──http──> nginx (frontend) ──http──> axiam-server
                    (LE leaf)       (SPA + /api proxy)          (plaintext)
```

Three things are wrong with it, in increasing order of severity.

### 1.1 Two proxies, and the rate limiter counted neither

`AXIAM__RATE_LIMIT__TRUSTED_HOPS` defaults to `0`
(`crates/axiam-api-rest/src/server.rs:40`,
`crates/axiam-api-rest/src/middleware/rate_limit_shared.rs:84`,
`crates/axiam-api-grpc/src/middleware/rate_limit.rs:100`). §4 works through the
arithmetic; the conclusion is that `0` is the **correct** value behind exactly
one appending proxy and the **wrong** value behind two. The old topology had
two, so:

* Caddy set `X-Forwarded-For: <client>`.
* nginx appended its own peer — Caddy — giving `X-Forwarded-For: <client>, <caddy>`.
* the extractor selected `idx = len - 1 - 0 = 1`, i.e. **Caddy's IP**, for every
  request from every client on the internet.

Every per-IP limit therefore shared one bucket. That includes `/auth/login`,
which `crates/axiam-api-rest/src/config/rate_limit.rs` deliberately keys per-IP
and never per-principal, because keying a login limiter on the identity being
attacked is how you let an attacker lock out a victim. Collapsed to one bucket
it does the opposite: one attacker's login flood exhausts the bucket that every
legitimate user shares, and the deployment gets a self-inflicted denial of
service that looks like a limiter working correctly.

This was not a latent risk. It was the live behaviour of the only deployment the
repository documented end to end.

### 1.2 Cleartext credentials on the container network

nginx proxied to `http://axiam-server:8090`. Every bearer token, every session
cookie, every password on its way to `/api/v1/auth/login`, and every OAuth2
client secret crossed the Docker bridge in cleartext. On a single-host Compose
stack the blast radius is "anything that can join the bridge network or read the
host's network namespace" — which on a home-lab Pi running other containers is
not a hypothetical.

The project's own standard (`CLAUDE.md`, "TLS 1.3 minimum for all external
communication") was satisfied only if you accepted that the container network is
not external. That is exactly the assumption that CONTRACT §8b already refused to
make for AMQP, where `AXIAM__AMQP__ALLOW_PLAINTEXT` was **removed** rather than
left as an escape hatch. The REST leg was held to a weaker standard than the
message bus for no reason anybody wrote down.

### 1.3 The documented Compose stack and the shipped Kubernetes manifests
disagreed about the shape of the deployment

`k8s/ingress.yml` has always routed by path:

| Path | Backend |
| --- | --- |
| `/api` | `axiam-server:8090` |
| `/oauth2` | `axiam-server:8090` |
| `/.well-known` | `axiam-server:8090` |
| `/` | `axiam-frontend:80` |

The Compose stack routed *everything* through nginx instead. So the two
supported deployments had different hop counts, different correct
`TRUSTED_HOPS` values, and different answers to "what reaches the backend" — and
only one of them was documented. Anything an operator learned from the Pi guide
was wrong on Kubernetes and vice versa.

**The change in one sentence: make the Compose/Pi deployment the same shape the
Kubernetes manifests already are, and put TLS on the backend leg in both.**

---

## 2. The topology

```
                         Internet
                            │
                            │ 443/TLS 1.3 — Let's Encrypt leaf for axiam-iam.duckdns.org
                            ▼
              ┌──────────────────────────────┐
              │  Caddy (host, systemd)       │   the only listener on 0.0.0.0
              └───┬──────────────────────┬───┘
                  │                      │
   /.well-known/acme-challenge/*         │  everything else routes by path
                  │                      │
                  ▼                      ├── /              ──http──> 127.0.0.1:8081
        /var/www/certbot                 │                            axiam-frontend
        (static, certbot webroot)        │                            (nginx, SPA only)
                                         │
                                         ├── /api/*         ─┐
                                         ├── /oauth2/*      ─┼─ 443/TLS 1.3 ─> 127.0.0.1:8090
                                         └── /.well-known/* ─┘   axiam-server
                                                                 (same LE leaf, TLS 1.3 only)

        /health, /ready, /health/jobs  ── not routed at the edge; see §6
```

Both container ports are bound to `127.0.0.1` on the host. Caddy is the only
process listening on a public interface.

### 2.1 What each hop is for, now that nginx no longer proxies the API

* **Caddy** terminates the public TLS connection, redirects `:80` → `:443`,
  serves the ACME webroot, and routes by path. It is the *only* thing that needs
  a public port, and it is a single-purpose, memory-safe binary with no access
  to AXIAM's secrets.
* **nginx (`axiam-frontend`)** serves the SPA and nothing else in this topology.
  Its `/api`, `/oauth2/` and `/.well-known` proxy blocks remain — the dev stack,
  the E2E suite and `docker compose` users reach the API *through* the frontend
  container, and `frontend/e2e/matrix/spa-routing.spec.ts` asserts they keep
  working — but on the Pi nothing routes to them, because Caddy claims those
  paths first.
* **axiam-server** terminates a TLS 1.3 connection from Caddy using the same
  Let's Encrypt leaf, and applies its own rate limiting, security headers and
  authentication.

### 2.2 Why not the alternatives

**Backend as the only public listener, serving the SPA itself.** Rejected. It
requires `actix-files` (not currently a dependency), makes the server's release
image carry the frontend build, and couples SPA deploys to backend restarts. It
would have made `TRUSTED_HOPS = 0` correct by removing every proxy, which is a
real benefit — but the same benefit is available here (§4) without putting a
static-asset server inside the process that holds the signing keys.

**Backend on a second public port or hostname.** Rejected. It makes the API a
second origin, which makes CORS load-bearing. `cors_allowed_origins` is a
`Vec<String>` and `load_config()` (`crates/axiam-server/src/main.rs`) calls
`.with_prefix("AXIAM").separator("__")` **without** `.list_separator()`, so
config-rs has no instruction for splitting a delimited env var into a sequence.
Before this design could tell an operator to set
`AXIAM__SERVER__CORS_ALLOWED_ORIGINS`, somebody would have to prove that key
parses from the environment at all. Keeping one origin means nobody has to, and
`cors_allowed_origins` stays empty in every documented topology — see §7.

**Keeping nginx in the API path and just adding TLS to that leg.** Rejected: it
keeps two proxies, so it keeps `TRUSTED_HOPS` non-zero and keeps the Compose and
Kubernetes topologies different. The whole point is to collapse to one hop.

---

## 3. Certificates: one ACME client, two consumers

Caddy obtains certificates automatically, which is why the old guide used it.
That convenience is now a problem: the backend needs the *same* leaf, and
Caddy's certificate storage layout is an internal implementation detail that
nothing should parse.

**Decision: certbot owns ACME. Caddy and `axiam-server` both consume
`/etc/letsencrypt/live/<domain>/`.**

* Caddy is configured with an explicit `tls <cert> <key>` and its own ACME is
  never engaged.
* Caddy serves `/.well-known/acme-challenge/*` from a webroot **before** the
  `/.well-known/*` route that goes to the backend. Order is load-bearing: AXIAM
  answers `/.well-known/openid-configuration`, certbot needs
  `/.well-known/acme-challenge/…`, and they share a prefix.
* A certbot `--deploy-hook` copies the leaf and key into a directory the
  container can read, reloads Caddy, and signals the server (§3.2).

One ACME client means one renewal to monitor, one place to look when it fails,
and no dependence on another program's storage layout.

### 3.1 Why the backend gets the public leaf rather than a private one

Caddy could verify a privately-issued backend certificate with
`tls_trusted_ca_cert_file`, and on Kubernetes that is what a service mesh or
cert-manager would do. For the Pi it would mean running a private CA whose
renewal nobody automates, to protect a hop that already has a publicly-trusted
certificate available for free. Reusing the leaf costs nothing, and Caddy
verifies it against the system trust store with no custom anchor at all — the
connection is `https://127.0.0.1:8090` with the SNI and verification name
overridden to the public hostname, which is a verification the public roots can
complete. Nothing anywhere in this design disables or bypasses certificate
verification.

### 3.2 Renewal, and why the leaf had to become hot-reloadable

`crates/axiam-server/src/tls.rs` had a hot-reload path for **client CA trust
anchors** only (`reload_trust_anchors`, `ReloadableClientCertVerifier`). The
server's own leaf was read once, in `build_rustls_server_config`, and handed to
rustls as `builder.with_single_cert(chain, key)`. rustls binds that for the
config's life and actix binds the config for the process's life, so the leaf
was fixed at boot.

Let's Encrypt certificates last 90 days and certbot renews at 60. A deployment
that never restarts serves an expired certificate on day 90. "Restart the
server every two months" is not a supported answer for an identity provider:
every restart drops in-flight requests and re-runs the boot path that reads
every secret out of Vault.

**Decision: implement leaf hot-reload, mirroring the existing trust-anchor
mechanism rather than inventing a second one.**

`with_single_cert` is replaced by `with_cert_resolver(Arc<ReloadableCertResolver>)`.
The resolver holds an `ArcSwap<Arc<CertifiedKey>>` and rustls consults it per
handshake, so a swap takes effect on the next connection with no restart and no
dropped request. This is the same shape as `ReloadableClientCertVerifier`, which
already holds `ArcSwap<Anchors>` and is already installed on every TLS listener.

Two triggers, because they fail in different ways:

* **`SIGHUP`** — the conventional operator hook, and what the certbot deploy
  hook sends. Immediate.
* **A periodic modification-time poll**, `AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS`,
  default `3600`, `0` to disable. This is the safety net for the case that
  actually happens: the deploy hook is misconfigured, or the container was
  restarted by an orchestrator that does not forward signals, and nobody
  notices until the certificate expires. An hourly `stat` of two files is free.

The swap is atomic and validated. `CertifiedKey` is fully constructed — both
files read, both parsed, the key proven to match the leaf — **before** anything
is swapped. A reload that fails leaves the previous certificate serving and logs
at `WARN`. This matters more than it looks: certbot writes `fullchain.pem` and
`privkey.pem` as two separate operations, so a poll can and will occasionally
observe a half-updated pair. Failing that reload and retrying on the next tick
is correct; swapping in a mismatched pair would take the listener down.

---

## 4. `TRUSTED_HOPS`: the derivation, and the doc bug it exposed

### 4.1 The rule

The extractor (`crates/axiam-api-rest/src/extractors/rate_limit.rs:67-92`)
selects `hops[len - 1 - trusted_hops]`, and falls back to `peer_addr()` when
`trusted_hops >= len`. The value to set follows from one fact about how proxies
write the header:

> A proxy appends **the address it received the request from**, not its own.
> nginx's `proxy_add_x_forwarded_for` is `$http_x_forwarded_for, $remote_addr`;
> Caddy's `reverse_proxy` and ingress-nginx do the same thing.

So the nearest proxy never appears in the header the server reads — it is the
socket peer. Therefore:

> **`TRUSTED_HOPS` = (number of reverse proxies between the client and the
> server) − 1.**
>
> Equivalently: the number of *proxy* addresses that appear in the
> `X-Forwarded-For` header the server receives.

Worked through, with a client that sends no header of its own:

| Proxies in front | Header the server sees | Correct `TRUSTED_HOPS` |
| --- | --- | --- |
| 0 (direct) | *(absent)* → `peer_addr()` | `0`, and see §4.3 |
| 1 — Caddy → server | `<client>` | **`0`** |
| 1 — ingress-nginx → server | `<client>` | **`0`** |
| 2 — Caddy → nginx → server | `<client>, <caddy>` | **`1`** |
| 3 — cloud LB → ingress → mesh → server | `<client>, <lb>, <ingress>` | **`2`** |

And with a client that spoofs `X-Forwarded-For: <attacker>` behind one proxy,
the proxy appends the real peer, giving `<attacker>, <client>`; `trusted_hops = 0`
selects index 1, the real client. The spoof is inert. Behind one appending proxy,
`0` is correct whether or not the client lies — which is the property worth
having, and it is now pinned by a test.

### 4.2 The doc comment was wrong

`crates/axiam-api-rest/src/extractors/rate_limit.rs:5-6` said the value "should
equal the number of trusted reverse-proxy hops (e.g. **1** for a single
nginx/ingress in front of the server)". Set `1` behind a single proxy and the
header has one entry, `1 >= 1`, and the extractor falls back to `peer_addr()` —
the proxy's address — collapsing every client into one bucket. The advice
produced exactly the failure the extractor exists to prevent.

The module's *example* is self-consistent (three entries, two proxies,
`trusted_hops = 1`); the prose generalised it by one off. Both the prose and the
struct-field doc are corrected, and
`crates/axiam-api-rest/tests/rate_limit_keying_test.rs` gains a case per row of
the table above so the rule cannot silently regress.

### 4.3 What each documented topology sets

| Deployment | Value | Why |
| --- | --- | --- |
| Pi / Compose prod (this design) | `0` (default) | Caddy is the only proxy |
| Kubernetes (`k8s/ingress.yml`) | `0` (default) | ingress-nginx is the only proxy |
| Kubernetes behind a cloud L7 LB | `1` | the LB's address appears in the header |
| Dev stack, E2E | `0` (default) | reached directly, or through one nginx |

The default is now correct for both shipped topologies — not by leaving it alone,
but because collapsing to one hop is what makes `0` right. `k8s/server/configmap.yml`
and `docker-compose.prod.yml` set it **explicitly** anyway, with the derivation
in a comment, because a value that is correct by accident is one nobody
re-derives when they add a load balancer.

### 4.4 The case the default cannot cover

A server reached with **no** proxy in front trusts nothing: the header is
ignored and `peer_addr()` is the key. That is safe. But it is only safe because
the server is not, in fact, exposed with the header honoured — and the struct
doc already says so. The new topology never exposes the backend without Caddy in
front, and `docker-compose.prod.yml` binds the backend to `127.0.0.1` so a
router misconfiguration cannot change that.

---

## 5. The transport between nginx and the backend

The backend now presents TLS. `docker/nginx.conf` proxied to
`http://axiam-server:8090`, which would break — not on the Pi, where nothing
routes through it any more, but in the dev stack and the E2E suite, which reach
the API through the frontend container and must keep working.

**Decision: template the upstream, so the frontend image works against a
plaintext *or* a TLS backend, and let the compose file choose.**

`docker/nginx.conf` becomes `docker/nginx.conf.template`, rendered at container
start by nginx's stock `envsubst` entrypoint (`/docker-entrypoint.d/20-envsubst-on-templates.sh`
in `nginx:*-alpine`). Two variables:

| Variable | Default | Prod |
| --- | --- | --- |
| `AXIAM_BACKEND_ORIGIN` | `http://axiam-server:8090` | `https://axiam-server:8090` |
| `AXIAM_BACKEND_SNI` | `axiam-server` | the public hostname |

When the origin is `https://`, the rendered config carries `proxy_ssl_verify on`,
`proxy_ssl_trusted_certificate` pointing at the system bundle, `proxy_ssl_name
$AXIAM_BACKEND_SNI` and `proxy_ssl_server_name on`. Verification is **on** in
every rendering; there is no `proxy_ssl_verify off` anywhere in this change and
no documented workaround that produces one. A deployment whose backend
certificate does not verify is a deployment that must fix its certificate.

The dev and E2E stacks set neither variable and get exactly the plaintext
behaviour they have today, so nothing about them changes.

### 5.1 Also fixed here, from the SSO session's handoff list

`claude_dev/federation-sso-login-design.md` §13 recorded two nginx findings for
this session:

* **No `form-action` in the CSP.** There is one now — it was in the header
  already; the finding was against an older revision. Verified rather than
  assumed, and the SAML/Apple IdP origins an operator must add are documented in
  the Pi guide rather than hard-coded, because they differ per deployment.
* **No `Referrer-Policy` on SPA responses.** There is one
  (`strict-origin-when-cross-origin`), likewise already present. Recorded here so
  the next person does not re-open a closed finding.

Items 3 (handoff-code sweeper) and 4 (`AXIAM__AUTH__OAUTH2_ISSUER_URL` must be
the public origin) are real and are addressed in the deployment artifacts and
the guide respectively.

---

## 6. Health endpoints

`/health`, `/ready` and `/health/jobs` are served at the **server root**, not
under `/api/v1`. In the old topology nginx proxied neither, so they were
reachable only from inside the container network — by accident, not by decision.

The path split makes that a decision, because Caddy has to be told about them
one way or the other.

**Decision: they are not routed at the edge.** Caddy routes `/api`, `/oauth2`
and `/.well-known` to the backend and `/` to the SPA; `/health` therefore lands
on the SPA route and returns the SPA's `index.html`, not the health payload. The
probes that need them — the Docker healthcheck, the Kubernetes liveness and
readiness probes — reach the backend directly on the container network, which is
where a health probe belongs.

The reasoning:

* `/health/jobs` reports per-job scheduler state: names, last-run timestamps,
  consecutive-failure counts. That is a free map of what a deployment runs and
  what is currently broken in it, handed to anyone who asks.
* `/ready` answers "can this instance reach its datastore" — a cheap oracle for
  whether an attack on the datastore is working.
* Neither is rate-limited the way `/api` is, because neither was ever
  internet-facing.
* An operator who *wants* external monitoring should point it at a path that
  requires a credential, or scrape from inside the network. The Pi guide shows
  the loopback probe.

This is the one place where "the backend is publicly exposed" would have
silently widened the attack surface, so it is called out in the threat model
(T-PBT-03) rather than left in a routing table.

---

## 7. CORS

Unnecessary, and deliberately still unset. The SPA at `https://<host>/` and the
API at `https://<host>/api` are the **same origin** — scheme, host and port all
match — so no preflight is ever issued and `cors_allowed_origins` stays empty.

This is worth stating because the topology *looks* like it should need CORS: two
processes, two TLS certificates, two containers. Origin is not about processes.

`AXIAM__AUTH__SSO_SPA_ORIGINS` is a different setting for a different problem
(where a federation handoff may redirect) and is unaffected.

---

## 8. Vault

The Compose stack runs Vault with `storage "file"` and no auto-unseal
(`docker/vault/vault.hcl`), and `just prod-up` writes the unseal key and root
token to `docker/.secrets/vault-init.json` and passes **that root token** to the
server as `AXIAM__AUTH__VAULT_TOKEN`.

Three things are wrong for a deployment anyone relies on:

1. **The unseal key lives on the same disk as the sealed data.** That is not
   Shamir's scheme with the shares stored badly; it is no seal at all. Anyone who
   can read the disk can unseal.
2. **The server runs as root.** `docs/deployment/vault.md` §5.4 already
   specifies a read-only `axiam` policy scoped to one path, and says in as many
   words that the seeding token and the serving token are different credentials.
   The Compose stack uses one token for both, and it is root.
3. **Every reboot leaves Vault sealed and `axiam-server` crash-looping**, because
   Docker does not re-evaluate `depends_on: service_healthy` on restart.

**Decision: the documented deployment moves to `storage "raft"`, a real
`operator init` with 5 Shamir shares and a threshold of 3, KV v2, the read-only
`axiam` policy from `vault.md` §5.4 for the serving token, and auto-unseal
configured before go-live.**

Raft rather than file storage because it is what HashiCorp supports, it takes
snapshots (`vault operator raft snapshot save`), and a single-node Raft cluster
is a supported configuration — the migration path to three nodes later does not
require re-seeding.

### 8.1 Auto-unseal on a home lab, honestly

`vault.md` §5.3 calls auto-unseal "the single most important production step and
the one most often deferred", and the honest problem is that Vault OSS's seal
types all need something outside the box:

| Option | Cost / requirement | Verdict for a Pi |
| --- | --- | --- |
| `seal "gcpckms"` | GCP Cloud KMS, ~$0.06/key/month + operations | **Recommended.** Cheapest, works from a home connection, no cloud footprint beyond one key. |
| `seal "awskms"` | AWS KMS, ~$1/key/month | Fine. Slightly pricier, same shape. |
| `seal "azurekeyvault"` | Azure Key Vault | Fine. |
| `seal "transit"` | A **second** Vault, elsewhere, already unsealed | Reasonable if you already run one. Pointing it at a second Vault on the same Pi solves nothing — that one needs unsealing too. |
| `seal "pkcs11"` (HSM/TPM) | Vault **Enterprise** only | Not available. Vault OSS cannot use a TPM to auto-unseal, whatever the Pi has. |
| A script that unseals from shares on the disk | none | **Not auto-unseal.** This is what the stack does today. It is the thing being fixed. |

So the documented answer is: **use a cloud KMS seal — GCP's costs pennies — or
transit-unseal against a Vault you already run somewhere else.** If an operator
will do neither, the supported statement is that they are running a
manually-unsealed Vault, that every reboot needs a human with three shares, and
that this is **not** a production deployment. The guide says that in those words.
What it never does is present the disk-resident-unseal-key arrangement as
production, or automate it and call the problem solved.

### 8.2 What `just prod-up` becomes

`prod-up` stays the developer's one-command local stack, and keeps its Shamir
ceremony — it is bringing up a throwaway stack on a laptop and a human is
watching. Two changes:

* It creates the read-only `axiam` policy and issues a **scoped, renewable
  token** for the server, instead of handing it the root token. Seeding keeps
  using a separate short-lived token with `create`/`update`, as `vault.md`
  already says it should.
* The banner it prints when it initialises says, once and unmissably, that the
  unseal key it just wrote to disk makes this stack non-production, and points
  at `vault.md` §5.3.

The Pi guide does **not** use `prod-up`'s Vault ceremony. It runs the real one.

---

## 9. What an existing deployment must do

This is a breaking change for anyone running the documented Compose stack.

| Change | Action required |
| --- | --- |
| Backend listens on TLS | Provide `AXIAM__SERVER__TLS__CERT_PATH`/`KEY_PATH`, or leave `ENABLED=false` and keep the old plaintext topology, which still works |
| Edge routes `/api` directly | Update the Caddyfile / ingress; the old "everything to the frontend" route keeps working but keeps the two-hop `TRUSTED_HOPS` problem |
| `TRUSTED_HOPS` | Re-derive with §4.1. Anyone on the old Caddy→nginx→server shape who left it at `0` was running a single global bucket and should set `1` if they keep that shape |
| Vault | A file-backed Vault keeps working; the migration to Raft is `operator raft snapshot`-based and is documented, not automatic |
| Server Vault token | A root token keeps working. Rotating to the scoped policy is the point, and needs a token issue |

Nothing in the change forces an existing deployment to move: TLS on the backend
is opt-in (`server.tls.enabled` still defaults to `false`), the nginx template
still defaults to plaintext, and `TRUSTED_HOPS` still defaults to `0`. What
changes is what the documentation *recommends*, and that the pieces needed to
follow the recommendation now exist.

---

## 10. Security argument for exposing the backend directly

The objection to putting an identity provider's API on the public internet is
that a reverse proxy is a bulkhead: it terminates the connection, normalises the
request, and gives you somewhere to put a WAF. Giving that up needs an argument.

The argument is that in this topology it is **not** given up — Caddy is still
there, still terminates the client's connection, and still routes. What changes
is that the leg from Caddy to the backend is TLS instead of cleartext, and that
the backend is one hop from the client instead of two. So the comparison is not
"proxy versus no proxy"; it is "one proxy versus two", and the second proxy was
buying nothing:

* nginx did not filter, rewrite or validate anything on the API path. Its
  `location /api` block set four headers and forwarded.
* It *cost* correctness: it was the hop that broke `TRUSTED_HOPS`, and the hop
  that made the Compose topology differ from the Kubernetes one.
* It was an extra process with the API's plaintext traffic passing through it.

What the backend gains by being one hop from the edge:

* **Rate limiting works.** §4. The limiter now sees real client addresses, so
  `/auth/login`'s per-IP limit means what it says.
* **No cleartext credentials anywhere**, including inside the host.
* **Uniform posture.** The same routing table, the same hop count and the same
  `TRUSTED_HOPS` derivation now describe Compose and Kubernetes.

What genuinely widens, and what is done about it:

| Widened | Mitigation |
| --- | --- |
| The backend's TLS stack is now reachable from the internet (through Caddy) | rustls, TLS 1.3 only, no 0-RTT (`max_early_data_size` stays 0 — the token endpoints are non-idempotent POSTs and early data is replayable) |
| The backend holds a certificate and a private key on disk | Mode-600, owned by the container user; renewed by certbot; hot-reloaded without a restart so nobody is tempted to automate a restart loop |
| Health endpoints could have become public | Deliberately not routed. §6 |
| A misconfigured edge could expose 8090 directly | Bound to `127.0.0.1` in the compose file; the guide's port-forward list names 443 and 80 only |

The residual risk that remains genuinely higher than before is the TLS
termination code path itself, and that is accepted: it is rustls, restricted to
TLS 1.3, with the same configuration the mTLS listener has been using in
production-shaped deployments since D3.

---

## 11. Implementation checklist

* [x] `ReloadableCertResolver` + `reload_leaf_certificate`, `SIGHUP`, mtime poll
* [x] `AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS`, documented on the website
* [x] `TRUSTED_HOPS` doc correction + topology tests
* [x] `docker/nginx.conf` → templated upstream, TLS-capable, verification always on
* [x] `docker-compose.prod.yml`: loopback binds, TLS knobs, explicit `TRUSTED_HOPS`
* [x] `k8s/server/configmap.yml`: explicit `TRUSTED_HOPS` with the derivation
* [x] `docker/vault/vault.hcl` → Raft; `prod-up` issues a scoped token
* [x] Pi guide rewritten
* [x] `docs/deployment/README.md`, `vault.md`, `docs/admin/`, website block content
* [x] `claude_dev/threat-model-stride.md`

No existing test is weakened, skipped or quarantined for any of it.
