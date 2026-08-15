# AXIAM Deployment Guide

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Last verified:** 2026-07-28

This guide gets an operator from zero to a running AXIAM stack, for both a
local Docker Compose setup and a Kubernetes deployment. It documents the
manifests and compose files that already ship in this repo — it does not
introduce new infrastructure. See also: [Admin Guide](../admin/README.md),
[PKI Guide](../pki/README.md), [API docs](../api/README.md).

## Docker (Compose)

[`docker/docker-compose.prod.yml`](../../docker/docker-compose.prod.yml) runs
the full stack (`axiam-server`, `axiam-frontend`, `surrealdb`, `rabbitmq`)
locally with a single command. It is documented in the file itself as
**not** intended for real production use (use the Kubernetes manifests in
[`k8s/`](../../k8s/) for that) — it exists to validate the stack end-to-end
on a workstation.

```bash
just prod-up
```

`just prod-up` (see [`justfile`](../../justfile)):

1. Generates a local-only Ed25519 JWT signing keypair under `docker/.secrets/`
   on first run (`openssl genpkey -algorithm ed25519` / `openssl pkey
   -pubout`), gitignored, and exports it into the shell as
   `AXIAM__AUTH__JWT_PRIVATE_KEY_PEM` / `AXIAM__AUTH__JWT_PUBLIC_KEY_PEM`.
2. Starts `docker compose -f docker/docker-compose.prod.yml up --build -d`.

`docker-compose.prod.yml` refuses to start without `AXIAM__DB__USERNAME`,
`AXIAM__DB__PASSWORD`, `RABBITMQ_DEFAULT_USER`, `RABBITMQ_DEFAULT_PASS`, and
the two JWT PEM vars being set in the shell environment (Compose's
`${VAR:?message}` syntax fails fast with a clear error instead of silently
using a default). This is the `docker/.secrets/` sourcing convention: secret
material lives in a gitignored local directory or is exported by `just
prod-up`, never hardcoded into the compose file.

Once up:
- Frontend: `http://localhost:8081`
- REST API: `http://localhost:8090`
- gRPC: `localhost:50051`

Stop with `just prod-down` (keeps volumes) or `just prod-clean` (also removes
volumes).

For local development (not production-like), use `just dev-up` /
`just dev-down` ([`docker/docker-compose.dev.yml`](../../docker/docker-compose.dev.yml))
to run only SurrealDB + RabbitMQ while running `axiam-server` natively.

## Kubernetes

The Kubernetes manifests live under [`k8s/`](../../k8s/) and are assembled by
[`k8s/kustomization.yml`](../../k8s/kustomization.yml):

```bash
kubectl apply -k k8s/
```

Key manifests:

- [`k8s/namespace.yml`](../../k8s/namespace.yml) — creates the `axiam`
  namespace with Pod Security Admission set to `restricted` (enforce + warn +
  audit) at the namespace level.
- [`k8s/server/deployment.yml`](../../k8s/server/deployment.yml),
  [`server/service.yml`](../../k8s/server/service.yml),
  [`server/hpa.yml`](../../k8s/server/hpa.yml),
  [`server/configmap.yml`](../../k8s/server/configmap.yml) — the AXIAM
  backend (REST + gRPC).
- [`k8s/frontend/deployment.yml`](../../k8s/frontend/deployment.yml),
  [`frontend/service.yml`](../../k8s/frontend/service.yml) — the React admin
  UI.
- [`k8s/surrealdb/statefulset.yml`](../../k8s/surrealdb/statefulset.yml),
  [`k8s/rabbitmq/statefulset.yml`](../../k8s/rabbitmq/statefulset.yml) — the
  stateful backing services.
- [`k8s/ingress.yml`](../../k8s/ingress.yml) — routes `/api`, `/oauth2`, and
  `/.well-known` to `axiam-server:8090`, and `/` to `axiam-frontend:80`.
  Update the `host:` (`axiam.example.com`) and TLS `secretName` before
  applying. gRPC (port 50051) is intentionally **not** exposed through
  Ingress — it is reachable only in-cluster via the `axiam-server` ClusterIP
  service.

Before applying, an operator must:
1. Populate [`k8s/server/secret.yml`](../../k8s/server/secret.yml) with real
   secret values (see **Required secrets & environment** below) — via a
   CI/CD secret store, `sealed-secrets`, or the `external-secrets` operator.
   Never commit real values into this file.
2. Adjust the `ingress-nginx` namespace selector placeholders in
   `k8s/network-policy/allow-ingress-to-frontend.yml` and
   `allow-ingress-to-server.yml` to match your actual ingress controller's
   namespace (see **Network policies** below).
3. Replace the placeholder CIDRs in
   [`k8s/network-policy/server-egress.yml`](../../k8s/network-policy/server-egress.yml)
   with your cluster's real pod/service CIDRs and your SMTP relay's CIDR.

## ⚠ Storage engine: a deployment MUST run a persistent SurrealDB datastore

**Requirement (MUST).** Every AXIAM deployment MUST start SurrealDB on a
persistent storage engine — `surrealkv:` or `rocksdb:`. A deployment MUST NOT
run the in-memory `memory` datastore, and MUST NOT set
`AXIAM__DB__ALLOW_MEMORY_ENGINE`.

This is a correctness requirement, not a durability preference. AXIAM has three
single-use credentials — UMA permission tickets, RFC 8628 device grants and
RFC 9126 PAR `request_uri`s — and each is redeemed by a guarded `UPDATE` inside
an explicit transaction, with a per-attempt nonce read back after the commit as
a second layer. The first layer only holds if the engine actually arbitrates the
write-write conflict between two concurrent redemptions. Measured with
[`tools/surreal-race-probe`](../../tools/surreal-race-probe/) — see
[`RESULTS.md`](../../tools/surreal-race-probe/RESULTS.md) for the version-pinned
numbers:

| Engine | Contended attempts | Rounds admitting two winners |
|---|---|---|
| `surrealkv` | 40 000 | 0 |
| `rocksdb` | 9 600 | 0 |
| `memory` | 9 600 | 23 |

`memory` is not failing to arbitrate — it aborts contended attempts at the same
54% rate the persistent engines do, then occasionally misses, silently, with
both callers receiving the pre-transition row. On that engine a double
redemption yields two RPTs from one authorization decision, two token sets from
one user approval, or a replayable authorization request
([ilpanich/axiam#302](https://github.com/ilpanich/axiam/issues/302)).

The shipped deployments already satisfy this — `docker-compose.dev.yml`,
`docker-compose.e2e.yml` and `docker-compose.prod.yml` all pass
`surrealkv:/data/axiam.db`, and
[`k8s/surrealdb/statefulset.yml`](../../k8s/surrealdb/statefulset.yml) passes
`surrealkv:/data/surreal.db`. If you author your own manifest, carry that
argument over.

**The server cannot verify this for you.** SurrealDB exposes no datastore
identity over the wire: neither `/version`, nor `INFO FOR ROOT` (including its
`system`, `nodes` and `config` sections), nor any `session::*` function names
the engine, as of SurrealDB 3.2.4. `axiam-server` therefore logs a WARN at
startup saying the engine could not be attested, and enforcement rests here,
with the operator. The check itself is already written
(`axiam_db::engine_attestation`): the day a SurrealDB release publishes the
engine name, the server will refuse to start against `memory` unless
`AXIAM__DB__ALLOW_MEMORY_ENGINE=true` is set, and a unit test fails on the next
dependency bump that makes the name available.

| Variable | Meaning |
|---|---|
| `AXIAM__DB__ALLOW_MEMORY_ENGINE` | **Development only.** `true` lets the server start against a positively-identified `memory` datastore instead of refusing. Never set it in a deployment; single-use redemption is not guaranteed when it is honoured. Unset (the default) fails closed. |

## Required secrets & environment

All AXIAM configuration keys use a **double underscore** after the `AXIAM`
prefix (e.g. `AXIAM__DB__USERNAME`) — this is how `config-rs` distinguishes
the env-var prefix from nested key separators. A single underscore is
silently ignored and the in-code default wins.

[`k8s/server/secret.yml`](../../k8s/server/secret.yml) is the canonical list
of required secret keys for a Kubernetes deployment (the `data:` values are
intentionally left blank in the committed file — fill them at deploy time,
never in git):

| Key | Purpose |
|---|---|
| `AXIAM__DB__USERNAME` | SurrealDB username |
| `AXIAM__DB__PASSWORD` | SurrealDB password |
| `AXIAM__AUTH__JWT_PRIVATE_KEY_PEM` | Ed25519 JWT signing private key (PEM). Generate with `openssl genpkey -algorithm ed25519` (see `just prod-up` for the exact commands). |
| `AXIAM__AUTH__JWT_PUBLIC_KEY_PEM` | Ed25519 JWT verification public key (PEM), paired with the private key above. |
| `AXIAM__AUTH__MFA_ENCRYPTION_KEY` | AES-256-GCM key (32 bytes, hex) encrypting TOTP MFA secrets at rest. Generate with `openssl rand -hex 32`. |
| `AXIAM__PKI__ENCRYPTION_KEY` | AES-256-GCM key (32 bytes, hex) encrypting CA signing private keys at rest. Generate with `openssl rand -hex 32`. |
| `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` | AES-256-GCM key (32 bytes, hex) encrypting SAML/OIDC federation client secrets at rest (SECHRD-09). Generate with `openssl rand -hex 32`. |
| `AXIAM__EMAIL_ENCRYPTION_KEY` | AES-256-GCM key (32 bytes, hex) encrypting email/SMTP provider secrets at rest. Generate with `openssl rand -hex 32`. |
| `AXIAM__GDPR_PSEUDONYM_PEPPER` | HMAC-SHA256 pepper (32 bytes, hex) used to pseudonymize audit-log actor identities on GDPR erasure. Generate with `openssl rand -hex 32`. |
| `AXIAM__AUTH__PEPPER` | Server pepper (plain string). Prepended before Argon2id password hashing, **and** keys client-secret hashing (OBS-1). **Mandatory in a release build** — the server refuses to start without it. Generate a long random string, e.g. `openssl rand -base64 32`. |
| `AXIAM__AUTH__PEPPER_PREVIOUS` | Outgoing pepper, **verify-only**, set for the duration of a pepper rotation. Unset outside a rotation. See below. |

Set every value to a placeholder such as `<set-in-secret-manager>` in any
example or template you author — never commit real key material, and never
reuse the same value across environments.

### ⚠ Rotating `AXIAM__AUTH__PEPPER`

**Read this before rotating.** The pepper is not only a password pepper: it
**keys the hash of every client secret** — every OAuth2 client and every service
account. Rotating it changes the key those hashes were computed under, so
without the procedure below, **every client secret in the deployment stops
verifying at once** and every one of them has to be re-issued.

`AXIAM__AUTH__PEPPER_PREVIOUS` makes the rotation drainable:

1. **Set** `AXIAM__AUTH__PEPPER` to the new value and `AXIAM__AUTH__PEPPER_PREVIOUS`
   to the outgoing one. Roll the fleet. Both are now accepted for verification;
   only the new one is ever written.
2. **Wait.** Each client secret is silently rewritten under the new pepper the
   first time its owner authenticates. Nothing has to be re-issued, and no
   downtime window is needed.
3. **Unset** `AXIAM__AUTH__PEPPER_PREVIOUS` once every client has authenticated
   at least once. Any client that has not will need its secret rotated normally.

Do **not** skip step 1 by rotating the value in place: there is no way to
recover a hash written under a pepper you no longer hold — only the digest was
ever stored, never the secret.

Password hashes are unaffected by this procedure: an Argon2id hash records its
own parameters and is verified against the presented password directly.

The AMQP connection string is not itself a `secret.yml` key; it is assembled
from `RABBITMQ_DEFAULT_USER` / `RABBITMQ_DEFAULT_PASS` (see
[`k8s/rabbitmq/secret.yml`](../../k8s/rabbitmq/secret.yml)) into
`AXIAM__AMQP__URL` at the deployment layer (see how
`docker-compose.prod.yml` does this for the Compose path).

## Argon2id hash concurrency (memory-DoS protection)

Password hashing/verification uses Argon2id with OWASP-recommended parameters
(`m=19456, t=2, p=1`). Each **in-flight** Argon2id operation allocates a
~19 MiB memory arena. Unbounded concurrency is therefore an unauthenticated
**memory-DoS** vector: a burst of concurrent logins multiplies that arena by
the number of simultaneous hashes. In benchmarking, an unbounded login flood
pegged 2 cores and drove server RSS to ~970 MiB (≈ 50 concurrent × 19 MiB),
approaching the 1024 MiB container cap, while p95 latency ballooned to ~2.1 s.

AXIAM bounds this with a process-wide semaphore shared across all CPU-bound
crypto (login, password change, password reset, and PKI keygen/sign). The
permit count caps peak concurrent arenas (and thus peak crypto RSS); a
configurable acquire timeout sheds load with an HTTP **503** backpressure
response instead of queueing unboundedly once every permit is held. The
Argon2id cost parameters themselves are never weakened to gain throughput.

| Key | Purpose |
|---|---|
| `AXIAM__AUTH__MAX_CONCURRENT_HASHES` | Max concurrent Argon2id hash/verify operations. `0` (default) = auto → `min(CPU cores, 4)`. Raise only if the host has spare memory headroom (peak crypto RSS ≈ this value × 19 MiB); lower to harden a tightly memory-capped container. |
| `AXIAM__AUTH__HASH_ACQUIRE_TIMEOUT_SECS` | Seconds a request waits for a hash permit before returning a `503 service_unavailable` backpressure error. Default `5`. Lower for faster load-shedding under attack; raise to tolerate longer queues before shedding. |

The 503 path preserves the SEC-026 username-enumeration defence: the login
"user not found" branch is subject to the same permit acquisition and timeout
as the real password-verify branch, so the two remain timing- and
status-indistinguishable under both normal and saturated load.

## Memory allocator (jemalloc, H4)

The released server image (`docker/Dockerfile.server`) links **jemalloc**
(via `tikv-jemallocator`) as the process-wide global allocator instead of the
platform default (glibc malloc). This is a build-time choice, not a runtime
setting — there is nothing to configure to get it; it ships this way.

**Why:** the platform default allocator does not return freed memory from a
burst of concurrent Argon2id login hashing (see **Argon2id hash concurrency**
above) back to the OS — retained RSS plateaus well above baseline and stays
there. The G6/D9 memory-retention experiment measured, on identical
workloads (a 50-VU login burst, 10-minute post-burst observation window):

| Variant | Baseline RSS | Peak RSS (during burst) | Retained RSS (post-burst plateau) | Retained above baseline |
|---|---|---|---|---|
| Default allocator (glibc malloc) | 68 MiB | 491 MiB | 376 MiB | +309 MiB |
| jemalloc | 69 MiB | 126 MiB | 86 MiB | +17 MiB |

jemalloc closed **94%** of the 309 MiB retention gap (ship threshold was
≥30%), also cutting the in-burst peak by ~74%, and with **no throughput or
latency regression** recorded against the default-allocator run. Full
numbers and methodology: [`claude_dev/memory-retention-experiment.md`](../../claude_dev/memory-retention-experiment.md) §6.

**`MALLOC_CONF` tuning: not needed.** jemalloc's out-of-the-box decay
settings (dirty pages purged back to the OS on jemalloc's default ~10s decay
timer) were sufficient to produce the numbers above — no
`MALLOC_CONF`/`_RJEM_MALLOC_CONF` environment variable is set in the image or
recommended for a default deployment. If a workload's retention profile ever
warrants tighter decay (e.g. `dirty_decay_ms:1000,muzzy_decay_ms:0` to purge
freed pages within ~1s of a burst subsiding, trading a few more `madvise`
syscalls and next-burst page-fault cost for faster reclaim), it can be set at
container-start time without a rebuild — see
`claude_dev/memory-retention-experiment.md` §5 for the trade-off — but treat
that as a measured opt-in, not a default recommendation.

**Escape hatch (musl/platform edge cases):** the Dockerfile's
`CARGO_FEATURES` build ARG defaults to `jemalloc`; build with
`--build-arg CARGO_FEATURES=` (empty) to fall back to the platform allocator
for a target where `tikv-jemallocator`/`jemalloc-sys` doesn't build or link
cleanly (SAML support is unaffected either way — it comes from the crate's
own `default = ["saml"]` feature, not this ARG):

```bash
docker build --build-arg CARGO_FEATURES= -f docker/Dockerfile.server -t axiam-server .
```

For a native (non-container) build, the crate feature itself stays opt-in
either way:

```bash
cargo build --release -p axiam-server                     # platform default allocator
cargo build --release -p axiam-server --features jemalloc  # jemalloc
```

A running server logs which allocator is active at startup
(`allocator=jemalloc` or `allocator=system` in the structured JSON log line
"Global allocator: ...") — check `docker logs`/`kubectl logs` to confirm
which one a given image was built with.

## Authorization decision cache (optional, D7)

An optional per-tenant cache of authorization decisions that skips the 3–4
SurrealDB round-trips per check. **Off by default**; enabling it changes
performance only, never the decision an endpoint returns.

| Key | Purpose |
|---|---|
| `AXIAM__AUTHZ__DECISION_CACHE_ENABLED` | Master switch. Default `false` — the authorization path is then byte-for-byte identical to a build without the cache. Set `true` to enable. |
| `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` | Cached-decision TTL in seconds (default `5`). Also the upper bound on revocation latency if an invalidation event is ever missed — keep it short. |
| `AXIAM__AUTHZ__DECISION_CACHE_MAX_ENTRIES` | Max cached decisions **per tenant** before FIFO eviction (default `10000`). Memory bound. |
| `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED` | Cross-replica invalidation over RabbitMQ. Default `false`. See [below](#cross-replica-invalidation-42). Requires the cache to be enabled. |
| `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_SKEW_SECS` | Freshness window for an inbound invalidation broadcast (default `30`). Only used when the broadcast channel is on. |

**Security posture (safe under AXIAM's default-deny / deny-override model):**
every access-*narrowing* mutation (role/grant/group/resource change) invalidates
the affected cache entries immediately, wired into the mutation handlers — so on
the replica that handled the mutation **no revocation leaves a stale allow**.
Since deny-override shipped, "narrowing" includes *adding* a grant whose effect
is `deny`; grant mutations flush the tenant regardless of effect, so that case
is covered on the same path. The TTL is the bounded-staleness backstop: a missed invalidation
self-heals within `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS`. Full rationale and
the per-mutation invalidation table are in the
[Admin Guide](../admin/README.md#authorization-decision-cache-optional-d7).

> **⚠ Multi-replica caveat — read before enabling, unless you also enable the
> broadcast channel below.** On its own the cache and its invalidation are
> **process-local**. "Revocation is immediate" is then a **single-process**
> property. Run two or more replicas and a revocation handled by one replica
> leaves the others serving the pre-revocation decision until their entries
> expire, so the **deployment's worst-case revocation latency becomes
> `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (default 5 s)** — on every read path,
> including the `RequirePermission` guard on the admin endpoints, and with no
> audit signal distinguishing a cached allow from a fresh one. In the
> Kubernetes manifests under `k8s/` (multi-replica by default) either set
> `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true` or leave
> `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=false`, unless a ≤ TTL revocation
> window is an accepted risk.

### Cross-replica invalidation (§4.2)

`AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true` (default `false`;
requires `AXIAM__AUTHZ__DECISION_CACHE_ENABLED=true`) removes the multi-replica
window above. Every invalidation a mutation triggers is published, HMAC-signed,
to the **fanout** exchange `axiam.authz.cache.invalidate`; each replica binds
its own exclusive auto-delete queue `axiam.authz.cache.invalidate.<replica-uuid>`
and applies what it receives. A revocation then propagates to *all* replicas in
broker-latency time instead of being bounded by the TTL — the TTL stays as the
backstop it always was.

**Requirements.** RabbitMQ must be reachable (it already is: AXIAM will not
start without it) and `AXIAM__AMQP__SIGNING_KEY` must be set — the same
mandatory §8 master key the authz/audit consumers use, from which a per-tenant
HKDF-SHA256 subkey is derived per message. Every replica must share that key.
No new broker credentials, exchange configuration or ports are needed beyond
permission to declare and bind on that exchange.

**Two behaviour changes you must plan for before flipping this on:**

| When | What happens | Why |
|---|---|---|
| The broker does not confirm an invalidation broadcast | The **mutation returns 503** (`service_unavailable`) | The database write is durable, but the other replicas were not told. Reporting success would be a lie, and would silently hand back the TTL window you enabled this to remove. These mutations are idempotent in the narrowing direction — **retry is safe**. |
| A replica's invalidation consumer is not connected (startup, broker outage, network partition) | That replica **stops serving from its cache** and evaluates every check against the database — correct, just slower — until it reconnects | Serving allows it can no longer invalidate is the security hole; hard-failing every authorization check would be a worse availability regression than the slowdown. |

**Both degraded modes are loud, not silent:**

* Losing the consumer logs `AuthZ decision cache UNTRUSTED …` at **ERROR**, and
  regaining it logs the matching INFO.
* The periodic `AuthZ decision cache stats (D7)` line carries `trusted=` and
  `bypassed=`. **`trusted=false`, or a rising `bypassed`, is the alert
  condition**: that replica is running uncached. Expect its authorization
  latency to return to the uncached numbers in
  [the authz read path guide](authz-read-path.md) while it is in that state.
* A 503 from a role/permission/group/resource/scope mutation with
  `"could not be broadcast to other replicas"` in the body means the broker,
  not the database, is the problem.

**Capacity.** One small transient message per access-narrowing mutation,
fanned out to N replicas. Administrative mutation rates are orders of magnitude
below authorization check rates, so this is negligible next to the existing
authz/audit/webhook traffic on the same broker.

**Clock sync.** Inbound broadcasts are rejected if their `issued_at` is outside
±`AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_SKEW_SECS` (default 30 s) of the
receiving replica's clock. Replicas should be NTP-synchronised (they already
must be for JWT `exp` handling). Raise the skew only if the true clock spread
is larger; a skew wider than necessary only lengthens the window in which a
captured message stays replay-eligible.

**What an attacker with publish rights to the exchange can do:** nothing but
evict cache entries, and only if they can forge a valid HMAC under the tenant's
derived subkey — messages are signed, version-floored (`key_version >= 2`),
freshness-gated and nonce-deduplicated per replica, so a captured broadcast
cannot be replayed for a thundering herd. A rejected message is logged and
counted but can **never** disable a replica's cache: trust follows the
consumer's connection state and nothing that arrives on the wire.

## Session-validation cache (optional, I6)

Access tokens are stateless JWTs, so every authenticated request re-reads the
`session` row behind the token's `jti` to confirm the session has not been
revoked (D-15 / REQ-7). That is **one SurrealDB read per authenticated
request** — including on `POST /api/v1/authz/check`, and it is *not* covered by
the authorization decision cache above. It is the reason enabling the decision
cache lifted gRPC authorization checks 13× but REST checks only 5% in benchmark
run 4: the two caches cover different round-trips, and the gRPC surface never
had this one (its interceptor validates the JWT signature and stops).

| Key | Purpose |
|---|---|
| `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS` | TTL in seconds for a *positive* session-validity answer. Default `0` = **disabled** (every request reads). Suggested starting value when enabling: `5`, matching the decision cache. |

What the cache stores and does not store:

* Only **positive** answers. A missing or revoked session is never cached, so a
  freshly-created session works immediately and a revoked one can never be
  resurrected by a stale negative.
* Entries carry the session row's own `expires_at` and are rejected exactly on
  time — **session expiry is never extended by this cache**, whatever the TTL.
* Every session-deleting method on the repository (`invalidate`, `consume`,
  `invalidate_user_sessions`, `invalidate_user_sessions_except`,
  `cleanup_expired`) drops the affected entries in the same call. There is no
  second code path that can delete a session row, so the invalidation cannot be
  forgotten by a future change.

> **⚠ Multi-replica caveat — identical to the decision cache.** The cache and
> its invalidation are **process-local**. On a single replica a logout or
> password change takes effect immediately. With two or more replicas, a
> session revoked on replica A stays acceptable on replicas B…N for up to
> `AXIAM__AUTH__SESSION_VALIDATION_CACHE_TTL_SECS`. Keep it at `0` in the
> multi-replica `k8s/` manifests unless that window is an accepted risk — and
> if you have already accepted the decision cache's window, accept this one at
> the same value, not a longer one.

## TCP_NODELAY on the REST listener (I5)

| Key | Purpose |
|---|---|
| `AXIAM__SERVER__TCP_NODELAY` | Set `TCP_NODELAY` (disable Nagle's algorithm) on accepted REST connections. Default `true`. |

actix-web does not set this socket option unless asked, so before AXIAM set it
explicitly the REST listener ran with Nagle **enabled** while the gRPC listener
(tonic, which defaults it on) did not. Nagle only costs anything when a
response reaches the socket as more than one write and the last write is a
partial segment — the kernel then holds that fragment until the peer
acknowledges the previous one, and Linux's delayed-ACK timer is 40 ms. That is
the leading explanation for the flat ~43 ms per-request floor benchmark run 4
measured on the TLS client-credentials endpoint with nothing saturated.

`false` restores the previous behaviour and exists so the effect can be
A/B-measured. There is no security implication either way.

## Rate limiting

Every authentication/OAuth2 endpoint is rate-limited (see
`crates/axiam-api-rest/src/config/rate_limit.rs`) by two cooperating layers:
a per-replica in-memory `Governor`, and a process-wide, write-behind shared
counter (`axiam_db::rate_limit_counter::SharedRateLimitCounter`,
`middleware::rate_limit_shared`) that closes the multi-replica gap. Both
layers derive their bucket key the same way. `GET /api/v1/users` is **not**
wrapped by either limiter — it was fixed to stop inheriting the `/users`
registration bucket (see the note at the end of this section) and now sits
unlimited, matching its siblings `GET /roles` and `GET /resources`.

| Key | Purpose |
|---|---|
| `AXIAM__RATE_LIMIT__LOGIN_PER_MIN` | Max `/auth/login` requests per minute per key (default `10`). |
| `AXIAM__RATE_LIMIT__REGISTER_PER_MIN` | Max register requests per minute per key (default `5`). |
| `AXIAM__RATE_LIMIT__TOKEN_PER_MIN` | Max `/oauth2/token` requests per minute per key (default `120`). |
| `AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN` | Max password-reset requests per minute per key (default `3`). |
| `AXIAM__RATE_LIMIT__MFA_PER_MIN` | Max MFA enroll/confirm/verify requests per minute per key (default `5`). |
| `AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN` | Max `/oauth2/introspect` requests per minute per key (default `600`). |
| `AXIAM__RATE_LIMIT__REVOKE_PER_MIN` | Max `/oauth2/revoke` requests per minute per key (default `60`). |
| `AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN` | Max authz-check requests per minute per key (default `1800`). |
| `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` | Max `/oauth2/device_authorization` requests per minute per IP (default `12`). |
| `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` | Max `/api/v1/device/verify` + `/device/decide` requests per minute per IP (default `10`). Bounded by the user-code brute-force assertion in `RateLimitConfig::validate`. |
| `AXIAM__RATE_LIMIT__SCIM_PER_MIN` | Max `/scim/v2/*` requests per minute per IP (default `600`). One bucket spans the whole SCIM surface — Users, Groups and the discovery endpoints, reads and writes alike. Sized as the REST twin of `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` (also 600/min): a privileged M2M provisioning client whose real cost is Argon2id. Never moved by `AXIAM__RATE_LIMIT__PROFILE`. |
| `AXIAM__RATE_LIMIT__TRUSTED_HOPS` | Number of trusted reverse-proxy hops to skip from the right of `X-Forwarded-For` when deriving the client IP (default `0` — set to `1` behind a single ingress/nginx). |
| `AXIAM__RATE_LIMIT__KEY` | Bucket-key derivation mode: `ip` (default) \| `client_id` \| `ip_client_id`. See below. |
| `AXIAM__RATE_LIMIT__PROFILE` | Deployment posture preset: `internet` (default — the shipped values above, unchanged) \| `gateway` \| `mesh`. Sets the machine-traffic family (key mode, token/introspect/revoke/authz, and the gRPC authz ceiling) coherently in one variable; never changes the human endpoints. See [Sizing your rate limits](rate-limit-sizing.md). |
| `AXIAM__RATE_LIMIT__SHARED` | Enables (`on`, default) or disables (`off`) the cross-replica shared counter. `off` is a **single-replica escape hatch**: it skips the shared layer entirely (no state, no store call, no flusher) and leaves the per-replica in-memory `Governor` as the sole limiter. Do not set `off` behind an HPA/multiple replicas — it re-opens the N× effective-limit multiplication the shared counter exists to close. |
| `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` | Write-behind flush interval for the shared counter, in milliseconds (default `1000`, clamped `50`–`60000`). Directly scales the cross-replica overshoot bound — see [Shared-store consistency model](#shared-store-consistency-model-write-behind) below. |

The gRPC listener has its own per-second ceilings, one bucket per gRPC
**method family** (reflection and health share a fixed, deliberately
generous 100/s bucket):

| Key | Purpose |
|---|---|
| `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` | Max `axiam.v1.AuthorizationService` requests per second per IP (default `100`). |
| `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` | Max `axiam.v1.UserInfoService` + `axiam.v1.TokenService` requests per second per IP. Unset = 5x the authz ceiling (default `500`). |
| `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` | Max `axiam.v1.UserService` requests per second per IP. Unset = a flat `10` (600/min per IP) in **every** posture — `ValidateCredentials` is Argon2id-bound, so this is a CPU guard on online password guessing and is deliberately not derived from the read-sized authz ceiling (SEC-079). |
| `AXIAM__GRPC__KEY` | Reserved for D8 parity; currently a no-op (the gRPC limiters are always per-IP — see [Sizing your rate limits § 5](rate-limit-sizing.md)). |

> **Which numbers should you actually run?** See
> **[Sizing your rate limits](rate-limit-sizing.md)** — the measured hardware
> envelope, the `gateway`/`mesh` presets, how to size by hand, and the
> security caveats that come with per-client keying. The shipped defaults are
> tuned for a small internet-facing deployment and are known to be too strict
> for a NAT'd M2M fleet.

### `AXIAM__RATE_LIMIT__KEY` — NAT'd-fleet key configurability (D8)

By default (`ip`) every rate-limit bucket keys on the caller's source IP —
this is the original, unchanged behavior for every endpoint.

For `/oauth2/token`, `/oauth2/revoke`, and `/oauth2/introspect` **only**,
`AXIAM__RATE_LIMIT__KEY` can instead key on the authenticating OAuth2
`client_id` (parsed from the form-encoded `client_secret_post` body, RFC 6749
§2.3.1):

- **`ip`** (default) — key on source IP alone, exactly as before. Many
  distinct OAuth2 clients egressing through one NAT gateway / corporate
  proxy / load balancer share a single bucket, so one noisy or
  misconfigured client can exhaust the token/introspect/revoke quota for
  every other client behind the same IP.
- **`client_id`** — key on the OAuth2 `client_id` alone. Each client gets an
  independent bucket regardless of source IP, which fixes the NAT collision
  above but means a client rotating IPs is still tracked as one bucket
  (intentional — the identity that matters here is the client, not the
  network path).
- **`ip_client_id`** — key on the `(ip, client_id)` pair. Each client gets an
  independent bucket **per IP it connects from**, so a compromised/leaked
  client credential being hammered from one attacker IP doesn't throttle the
  same client operating legitimately from its normal IP.

**`/auth/login` (and every other rate-limited endpoint) always keys per-IP,
regardless of this setting.** Login authenticates a *user* via
username/password — there is no OAuth2 client identity anywhere in that
request to key on. This is enforced in code (`server.rs` wires `/auth/login`
with the plain, IP-only `build_governor`/`RateLimitShared::new`
constructors, which never read `AXIAM__RATE_LIMIT__KEY`) and is not
configurable — see `RateLimitKeyMode`'s doc comment in
`crates/axiam-api-rest/src/config/rate_limit.rs` for the full rationale.

When a `client_id`/`ip_client_id`-mode request has no parseable `client_id`
(malformed body, wrong content type, etc.), the rate limiter fails **safe**
by falling back to the IP key for that request — it never disables rate
limiting outright.

### Shared-store consistency model (write-behind)

The shared counter used to perform one synchronous SurrealDB `UPSERT` per
request, awaited **before** the handler ran, on every request to the six
wrapped endpoints (`POST /api/v1/authz/check`, `/oauth2/token`,
`/oauth2/introspect`, `/oauth2/revoke`, `/auth/login`, and — until fixed, see
below — `GET /api/v1/users`). That write put the datastore's own write
latency directly on the request path: measured at **16–21 ops/s at any
concurrency from 1 to 40 clients** against a ~40 ms write on the
investigation host, while structurally identical unwrapped endpoints ran at
68–4 248 ops/s (`claude_dev/postseed-transient-investigation.md`, task H2).
That per-request write is gone. `SharedRateLimitCounter`
(`axiam_db::rate_limit_counter`) now decides synchronously from an in-process
sharded count (`shared_count + pending > limit`, no datastore round trip, no
`await`) and a single background flusher coalesces every bucket's
accumulated increments into **one** datastore write per `(bucket, window)`
per `AXIAM__RATE_LIMIT__SHARED_SYNC_MS`.

**Security bound.** Cross-replica enforcement is therefore **eventual**
rather than synchronous. Quoting the module docs verbatim, the worst-case
overshoot beyond the configured limit, before the counts converge, is
bounded by approximately

```text
(replicas - 1) × arrival_rate_per_replica × sync_interval
```

and is **zero on a single replica** (`replicas - 1 = 0`, so local counting is
exact and this layer is as strict as the previous synchronous
implementation). Worked example from the module docs: limit 100/min, 4
replicas, `sync_interval` 1 s, aggregate arrival 40 req/s ⇒ worst case ≈
`3 × 10 × 1 s` = **~30 requests of overshoot** inside a 60 s window (≈30% of
the limit), shrinking linearly as `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` is
lowered. Overshoot is additionally capped by the **per-replica in-memory
`Governor` on the same endpoint**, which is completely unchanged by this
design: it still runs on every wrapped endpoint and still makes a full,
independent per-replica decision — the shared layer's job is only to stop
the *aggregate* across replicas from reaching `replicas × limit`, and after
one `sync_interval` it does.

**Store-outage semantics changed.** Before this change, a store error on the
per-request write made the middleware fail open for that one request (warn,
forward to the in-memory governor) — so a request during an outage was
allowed regardless of the configured limit. Now the request path never talks
to the store at all; an outage is discovered by the background flusher, and
`check()` keeps deciding from the (still valid) local count against the
*same* configured limit. Concretely: **`limit = 0` plus an unreachable store
now denies**, where the previous design would have allowed — "the store is
unreachable" must not be read as "the limit is disabled." This is the one
behavioral delta in an otherwise unchanged fail-open posture: fail-open on
store errors remains the **one deliberate fail-open exception** in the
codebase (D-01b / T-24-42 accepted risk); every other control still fails
closed, and the in-memory governor still guarantees an outage never
hard-blocks auth traffic or surfaces a 5xx.

**Upgrade note.** The bucket key (`{endpoint}:{key_part}`) and the
`rate_limit_bucket` table are byte-for-byte unchanged, so an in-place upgrade
keeps counting against the same rows — no migration, no reset of in-flight
windows.

**The gRPC listener holds its own counter, not a shared one.** The gRPC
`GrpcSharedRateLimitLayer` (server-wide tower layer) and the REST
`RateLimitShared` middleware each own an independent
`SharedRateLimitCounter` instance in the same process, both reading the same
`AXIAM__RATE_LIMIT__SHARED*` env vars. This is intentional, not two competing
counters: gRPC only ever writes `grpc_authz:<ip>` keys while REST writes
`<rest_endpoint>:<key_part>` keys, so the two keyspaces never overlap and
neither instance can fragment the other's local count.

**Observability.** At startup the server logs one of:

```
shared rate-limit counter ACTIVE (write-behind); one datastore write per
bucket per sync interval instead of one per request
  sync_interval_ms=1000 shards=16
```

or, with `AXIAM__RATE_LIMIT__SHARED=off`:

```
shared rate-limit counter DISABLED (AXIAM__RATE_LIMIT__SHARED=off); the
per-replica in-memory governor is the sole rate limiter
```

Two `warn`-level alarms can fire afterward (each logged **once**, latched,
never per request, and never with the raw bucket key — T-24-43, since the
key embeds a client IP/`client_id`):

- the flusher's datastore write failed during a flush pass ("shared
  rate-limit store unreachable during write-behind flush") — cross-replica
  convergence is paused, decisions keep being served from local counts;
- the flusher has fallen behind its own `sync_interval` ("write-behind
  flusher is falling behind") — a bucket with pending work has gone
  unflushed for 5+ sync intervals, meaning the overshoot bound above no
  longer holds until it clears.

**Sizing implication.** Before this change, the synchronous per-request
write made each wrapped endpoint's throughput ceiling equal to the
datastore's own write latency, not the server's request-handling capacity —
measured on the investigation host at **16–21 ops/s against a ~40 ms
write**, regardless of concurrency, replicas, or connection-pool size. That
ceiling no longer applies: the request path performs no datastore I/O for
the rate-limit decision at all. Post-fix throughput has not yet been
re-measured end-to-end; when it is, the numbers will land in
`claude_dev/rate-limit-fix-verification.md` (not yet present at the time of
writing — produced by a separate, concurrent verification task).

**`GET /api/v1/users` fixed.** This endpoint used to be wrapped by the same
actix resource as `POST /users` and so inherited the `users_create`
registration bucket (`AXIAM__RATE_LIMIT__REGISTER_PER_MIN`, 5/min/IP in the
shipped posture) for a plain list read. It is now registered as a separate,
unlimited resource, matching the posture of its siblings `GET /roles` and
`GET /resources`.

## TLS termination

AXIAM supports two TLS patterns (ASVS V9.1.2/V9.1.3). Both enforce TLS 1.3 as
the minimum negotiated version; TLS 1.3 cipher suites are all ASVS-approved, so
no manual cipher-suite list is required.

**1. Proxy-terminated TLS (recommended, default).** The server binds plaintext
on `:8090` and an ingress controller / load balancer / reverse proxy terminates
TLS in front of it (this is how the Kubernetes manifests and
`docker-compose.prod.yml` are wired — see the ingress `TLS secretName` at the
top of this document). Configure the proxy to require TLS 1.3, e.g. for Nginx:

```nginx
ssl_protocols TLSv1.3;
```

or Caddy (`tls` is TLS 1.3-capable by default; pin the minimum explicitly):

```caddy
tls {
    protocols tls1.3
}
```

The server needs no TLS configuration in this mode.

**2. Direct TLS in the server process (opt-in).** For deployments that terminate
TLS in the server itself, set the following and the listener binds with rustls
restricted to **TLS 1.3 only**:

| Key | Purpose |
|---|---|
| `AXIAM__SERVER__TLS__ENABLED` | `true` to enable in-process TLS (default `false`). |
| `AXIAM__SERVER__TLS__CERT_PATH` | Path to the PEM certificate chain (leaf first). |
| `AXIAM__SERVER__TLS__KEY_PATH` | Path to the PEM private key (PKCS#8, PKCS#1, or SEC1). |

When `ENABLED` is `true`, both paths are mandatory and must point at readable,
well-formed PEM files — the server **fails fast at startup** (it never falls back
to plaintext) on a missing path, an unreadable/malformed file, an empty
certificate chain, or a certificate/key mismatch. Mount the cert and key as
secret volumes; never commit key material to git.

## Network policies

[`k8s/network-policy/`](../../k8s/network-policy/) implements a **default-deny**
posture (`policyTypes: [Ingress, Egress]` on an empty `podSelector`, i.e. no
implicit rule = deny everything), then opens narrow, explicit exceptions:

| Policy file | Effect |
|---|---|
| [`default-deny.yml`](../../k8s/network-policy/default-deny.yml) | Denies all ingress and egress for every pod in the `axiam` namespace unless another policy explicitly allows it. |
| [`allow-dns-egress.yml`](../../k8s/network-policy/allow-dns-egress.yml) | Allows every pod to resolve DNS (UDP/TCP 53) against `kube-system` — without this, in-cluster service-name resolution breaks. |
| [`allow-ingress-to-frontend.yml`](../../k8s/network-policy/allow-ingress-to-frontend.yml) | Allows the ingress controller (namespace selector, default `ingress-nginx` — adjust to match your cluster) to reach `axiam-frontend:8080`. |
| [`allow-ingress-to-server.yml`](../../k8s/network-policy/allow-ingress-to-server.yml) | Allows the ingress controller to reach `axiam-server:8090`. |
| [`allow-ingress-to-rabbitmq.yml`](../../k8s/network-policy/allow-ingress-to-rabbitmq.yml) | Restricts RabbitMQ (`5672`) ingress to pods labeled `component: server` only. |
| [`allow-ingress-to-surrealdb.yml`](../../k8s/network-policy/allow-ingress-to-surrealdb.yml) | Restricts SurrealDB (`8000`) ingress to pods labeled `component: server` only. |
| [`server-egress.yml`](../../k8s/network-policy/server-egress.yml) | Allows `axiam-server` to reach SurrealDB (`8000`), RabbitMQ (`5672`), external HTTPS on `443` (OIDC JWKS, SAML IdPs, email APIs — RFC1918/CGN ranges and the cluster's pod/service CIDRs are explicitly excluded to prevent lateral movement), and an operator-configured SMTP relay on `25`/`465`/`587`. The SMTP rule ships pointed at a placeholder RFC 5737 TEST-NET-1 CIDR (`192.0.2.0/24`) — mail will not send until the operator replaces it with their real relay's CIDR; **never widen this to `0.0.0.0/0`**. |

No pod in the `axiam` namespace can reach anything not explicitly listed
above — this is intentional fail-closed network isolation, not an
oversight. When adding a new integration (e.g. a different SMTP relay or an
external IdP on a new IP range), extend `server-egress.yml` narrowly rather
than relaxing the default-deny baseline.

## Securing the broker (AMQP over TLS)

AXIAM's async plane — authorization requests, audit events, outbound mail,
webhook dispatch, cross-replica cache invalidation — all crosses RabbitMQ. Six
SDKs consume AMQP directly, so that traffic crosses service boundaries by
design.

### What HMAC does and does not do

The AMQP layer signs messages with HMAC-SHA256 and rejects replays. That gives
**authenticity and replay protection** — a forged `AuthzRequest` is rejected,
a captured one cannot be re-sent. It gives **no confidentiality**: a signed
message still names its subject, resource and action in cleartext on the wire,
and a signed audit event still carries the audit record.

TLS supplies the confidentiality. It does not supply HMAC's property, because
TLS terminates at the broker and the broker then re-sends — only an end-to-end
signature survives that hop. **Run both.**

### Compose

`just prod-up` handles it. It calls `just prod-broker-certs`, which generates a
private CA and a broker certificate into `docker/.secrets/broker-tls/` (already
gitignored), and the stack comes up on `amqps://…:5671` with the plaintext
listener disabled and TLS 1.3 pinned.

Bring your own certificate instead by dropping `ca.pem`, `server.pem` and
`server.key` into that directory before the first `prod-up`; the generator
leaves existing material alone. Certificates from `axiam-pki`'s own
organization CA work identically and are good dogfooding — one trust root to
rotate rather than two.

To rotate: delete `docker/.secrets/broker-tls/`, re-run
`just prod-broker-certs`, restart both containers. The generated certificates
are valid for 825 days.

### Kubernetes

The manifests ship the TLS shape already: the broker listens on 5671 only, the
Service publishes only 5671, both NetworkPolicies allow only 5671, and the
server mounts the CA bundle read-only.

What you supply is the `rabbitmq-broker-tls` Secret, with keys `tls.crt`,
`tls.key` and `ca.crt`.

**cert-manager is the recommended issuer.** A `Certificate` resource with
`dnsNames: [rabbitmq, rabbitmq.axiam.svc.cluster.local]` writing into that
Secret gives you automatic renewal — which matters more here than it looks: a
broker certificate that silently expires takes the entire async plane down at
once, and does it at renewal time rather than at deploy time, when nobody is
watching. Bring-your-own works too; just remember that you now own the renewal.

The server pod mounts **only** `ca.crt` from that Secret. It verifies the
broker; it has no business holding the broker's private key.

### There is no way to skip verification

`AmqpTlsConfig` has no `verify_peer: false`, and this is not an omission to be
filled in later. A verification-skip switch appears in a dev compose file,
works, and travels unchanged into production, where it turns TLS into an
expensive no-op against exactly the attacker TLS exists to stop.
`AXIAM__AMQP__TLS__CA_CERT_PATH` covers the legitimate reason people reach for
it — a self-signed or private-CA broker certificate — without covering the
rest.

An `amqps://` connection that fails verification is an error. It does not
retry in the clear.

### Dev, e2e and bench stay plaintext, deliberately

`docker/docker-compose.dev.yml`, the e2e stack and the benchmark target still
use `amqp://`. **A release binary refuses a plaintext broker URL** unless
`AXIAM__AMQP__ALLOW_PLAINTEXT=true` is set, which logs a prominent warning
naming exactly what is now readable on the wire — so all three set that flag
explicitly, each with a comment giving its own reason.

Note that the flag is genuinely required there. These stacks run the *published
release image*, not a debug build, so the guard applies to them exactly as it
applies to production; being "only dev" earns no exemption from it. The
`cfg!(debug_assertions)` pass-through covers `cargo test` and `cargo run`, which
is why the CI test and coverage jobs need no flag.

`scripts/check-amqp-transport.py` enforces this at PR time, and CI runs it in
the Security Scan job. It does not require TLS — plaintext on an ephemeral CI
broker is a reasonable trade — only that a stack using `amqp://` says so
explicitly. Without it the sole symptom of a missed stack is a container that
refuses to boot, which is easy to misread as an unrelated infrastructure fault.

### Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `AXIAM__AMQP__URL` | `amqp://localhost:5672` | `amqps://` selects TLS (port 5671). |
| `AXIAM__AMQP__TLS__CA_CERT_PATH` | *(unset)* | PEM bundle for the broker's issuing CA. Unset = system roots. |
| `AXIAM__AMQP__TLS__CLIENT_CERT_PATH` | *(unset)* | PEM client certificate, for mutual TLS. Requires the key. |
| `AXIAM__AMQP__TLS__CLIENT_KEY_PATH` | *(unset)* | PEM client key. Requires the certificate. |
| `AXIAM__AMQP__ALLOW_PLAINTEXT` | `false` | Permit `amqp://` in a release build. |

## Software Bill of Materials (SBOM)

Every tagged release (`v*`) publishes a CycloneDX 1.5 SBOM for each Cargo
workspace member plus one for the frontend's npm dependency tree, generated
by the `sbom` job in
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) via
`cargo cyclonedx` and `@cyclonedx/cyclonedx-npm` respectively. They are
attached as downloadable files (`*.cdx.json`) on the corresponding [GitHub
Release](https://github.com/ilpanich/axiam/releases), alongside the binary
tarballs — no separate registry or artifact host to check.

CycloneDX (over SPDX) because both ecosystems here already have an actively
maintained, OWASP-native generator that installs from the public
crates.io/npm registries, keeping the two SBOMs in one consistent format
with no paid registry or license key involved.

This satisfies CRA's SBOM/supply-chain-transparency expectation and ISO
27001 Annex A.5 asset-inventory theme; see `docs/compliance/FINDINGS.md`
(#SBOM-01) and `docs/compliance/asvs-l2-checklist.md` (§V14, SBOM-01 row)
for the compliance disposition.
