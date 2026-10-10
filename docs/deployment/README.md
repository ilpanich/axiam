# AXIAM Deployment Guide

**Milestone:** `1.0.0` — first stable release
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

For a single node that does not need a message broker there is a smaller
stack, [`docker/docker-compose.minimal.yml`](../../docker/docker-compose.minimal.yml)
(`just minimal-up`): SurrealDB and `axiam-server` only, with
`AXIAM__AMQP__ENABLED=false`. It has real limits — read
[Minimal profile (no broker)](#minimal-profile-no-broker) before choosing it.

`just prod-up` (see [`justfile`](../../justfile)):

1. Mints the SurrealDB and RabbitMQ credentials on first run into
   `docker/.secrets/stack-credentials.env` (gitignored, mode 600) and sources
   them. They are persisted rather than regenerated per run because both
   services only honour these on the first boot of an empty data volume — a
   fresh password on the second run locks the server out of its own datastore.
2. Generates a local-only Ed25519 JWT signing keypair under `docker/.secrets/`
   on first run (`openssl genpkey -algorithm ed25519` / `openssl pkey
   -pubout`), gitignored, and exports it into the shell as
   `AXIAM__AUTH__JWT_PRIVATE_KEY_PEM` / `AXIAM__AUTH__JWT_PUBLIC_KEY_PEM`.
3. Sets `AXIAM_IMAGE_TAG` to the workspace version in `Cargo.toml` unless it is
   already exported.
4. Brings Vault up, initialises, unseals and seeds it, then exports the root
   token as `AXIAM__AUTH__VAULT_TOKEN`.
5. Starts `docker compose -f docker/docker-compose.prod.yml up -d`.

`axiam-server` and `axiam-frontend` are **pulled** from the project's public
GitHub registry (`ghcr.io/ilpanich/axiam/server`, `.../frontend`) — the same
multi-arch, Trivy-scanned, cosign-signed images `release.yml` publishes — rather
than built from the working tree. Pin a different release with
`AXIAM_IMAGE_TAG=<tag> just prod-up`; to build from local source instead,
uncomment the `build:` blocks on those two services in
`docker-compose.prod.yml` and restore `--build` in the `prod-up` recipe.

A stable release is published under three tags — `1.0.0`, `1.0` and `latest` —
and a pre-release only under its exact version (`release.yml` applies the moving
`1.0` and `latest` tags to stable releases alone). **Pin the exact version in
production**: `latest` and `1.0` move with every release, and an upgrade should
be a change you made on purpose and read the CHANGELOG for. `AXIAM_IMAGE_TAG` is
**required** all the same — the compose file refuses to start without it — and
`just prod-up` supplies it from the workspace version so there is only one place
a release number lives.

`docker-compose.prod.yml` refuses to start without `AXIAM_IMAGE_TAG`,
`AXIAM__DB__USERNAME`, `AXIAM__DB__PASSWORD`, `RABBITMQ_DEFAULT_USER`,
`RABBITMQ_DEFAULT_PASS`, `AXIAM__AUTH__VAULT_TOKEN` and the two JWT PEM vars
being set in the shell environment (Compose's `${VAR:?message}` syntax fails
fast with a clear error instead of silently using a default). This is the
`docker/.secrets/` sourcing convention: secret material lives in a gitignored
local directory or is exported by `just prod-up`, never hardcoded into the
compose file. Compose interpolates the *whole* file on every invocation, even
one that targets a single service, so raw `docker compose` against this file is
not a supported path — `just prod-up` is.

Once up:
- Frontend: `http://localhost:8081`
- REST API: `http://localhost:8090`
- gRPC: `localhost:50051`

Stop with `just prod-down` (keeps volumes) or `just prod-clean` (also removes
volumes).

The stack has one volume the server writes to besides the datastore's:
`gdpr-audit-dlq`, the audit dead-letter file (`AXIAM__GDPR_AUDIT_DLQ_FILE`). It
holds audit rows the datastore refused, so `just prod-clean` deletes the only
copy of any not yet replayed — see [the audit dead-letter
file](#the-audit-dead-letter-file) before cleaning a stack that has had a
datastore outage.

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
- [`k8s/ingress.yml`](../../k8s/ingress.yml) — **two** Ingress objects sharing
  one host. `axiam-ingress-api` routes `/api`, `/oauth2` and `/.well-known` to
  `axiam-server:8090` **over HTTPS, verified against the in-cluster CA**;
  `axiam-ingress-app` routes `/` to `axiam-frontend:80` over HTTP. The split is
  forced: `backend-protocol` and the `proxy-ssl-*` annotations are per-Ingress,
  and the two upstreams do not speak the same protocol. Update the `host:`
  (`axiam.example.com`, four occurrences) and the TLS `secretName` before
  applying. gRPC (port 50051) is intentionally **not** exposed through Ingress —
  it is reachable only in-cluster via the `axiam-server` ClusterIP service.

- [`k8s/certs/`](../../k8s/certs/) — **cert-manager `Certificate` and `Issuer`
  examples, and a hard requirement rather than an extra.** Three Secrets are
  consumed by the manifests above and produced by nothing in `k8s/`:
  `vault-tls` (Vault's listener), `rabbitmq-broker-tls` (the broker's leaf, plus
  the `ca.crt` the server projects to verify it) and `axiam-server-tls` (the
  backend's own TLS 1.3 listener). Without them the Vault and RabbitMQ pods stay
  `ContainerCreating` and the server cannot terminate TLS. This directory is
  deliberately **not** in `kustomization.yml`, because applying a cert-manager
  custom resource to a cluster without its CRDs fails; apply it as a second
  step. See [`k8s/certs/README.md`](../../k8s/certs/README.md) — it also covers
  bringing your own CA instead, and the renewal semantics, which are not the
  same for all four consumers.
- **On a single Raspberry Pi 5 with k3s**, all of this is scripted:
  [`docs/deployment/rpi5-k3s.md`](rpi5-k3s.md) and `infra/rpi5-k3s/`.

The server pod mounts one volume it writes to: an `emptyDir` for the audit
dead-letter file (`AXIAM__GDPR_AUDIT_DLQ_FILE`, set in the ConfigMap). It is lost
with the pod, so replay it before a rollout while it holds rows — see [the audit
dead-letter file](#the-audit-dead-letter-file) for why it is not a claim and what
to do if it must be. Its `sizeLimit` is enforced by evicting the pod, which
deletes the file, so the server's budget for it
(`AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES`, 192 MiB in the ConfigMap) stays below the
limit.

Before applying, an operator must:
0. Install cert-manager and apply [`k8s/certs/`](../../k8s/certs/) (or create
   the three TLS Secrets some other way). Nothing below works without them.
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

**Secrets follow one further rule.** Every cryptographic secret is fetched
through the pluggable secret provider, which addresses secrets by a *logical*
name (`pki_encryption_key`); under the default `env` provider that name
resolves to `AXIAM__AUTH__<KEY>`, uppercased — so the CA encryption key is
`AXIAM__AUTH__PKI_ENCRYPTION_KEY` and **not** `AXIAM__PKI__ENCRYPTION_KEY`.
There are exactly three exceptions, the credentials that already shipped under
another spelling and keep it: `db_username` → `AXIAM__DB__USERNAME`,
`db_password` → `AXIAM__DB__PASSWORD`, `amqp_url` → `AXIAM__AMQP__URL`.
Nothing else has a second accepted name. A variable outside this rule is read
by nothing: the value is set, the feature stays off, and the fault looks like
the feature — so the server now logs a `WARN` naming both spellings if it finds
one of the four that this documentation previously got wrong
(`AXIAM__PKI__ENCRYPTION_KEY`, `AXIAM__EMAIL_ENCRYPTION_KEY`,
`AXIAM__GDPR_PSEUDONYM_PEPPER`, `AXIAM__FEDERATION_ENCRYPTION_KEY`).

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
| `AXIAM__AUTH__PKI_ENCRYPTION_KEY` | AES-256-GCM key (32 bytes, hex) encrypting CA signing private keys at rest. Generate with `openssl rand -hex 32`. |
| `AXIAM__AUTH__FEDERATION_ENCRYPTION_KEY` | AES-256-GCM key (32 bytes, hex) encrypting SAML/OIDC federation client secrets at rest (SECHRD-09). Generate with `openssl rand -hex 32`. |
| `AXIAM__AUTH__EMAIL_ENCRYPTION_KEY` | AES-256-GCM key (32 bytes, hex) encrypting email/SMTP provider secrets at rest. Generate with `openssl rand -hex 32`. |
| `AXIAM__AUTH__DIRECTORY_ENCRYPTION_KEY` | **Optional.** AES-256-GCM key (32 bytes, hex) encrypting each tenant's LDAP / Active Directory bind secret at rest. Without it the directory feature is unavailable: a directory write that carries a bind secret (every create, every move of the connection) is refused with `503`, the log line — not the response — names this key, reads, `DELETE` and the sync status still answer, and the server still starts. Generate with `openssl rand -hex 32`. |
| `AXIAM__AUTH__SAML_PAIRWISE_KEY` | **Optional, and must never change once set.** HMAC-SHA256 key (32 bytes, hex) deriving the persistent, pairwise SAML `NameID` the SAML identity provider gives each user at each service provider (D-22). Without it a sign-on to a service provider whose `NameID` policy is the persistent default is refused (`Responder`); an `emailAddress` service provider still works, and the server still starts. **Rotating or losing it gives every user a new, unknown account at every such service provider** — treat it like a database you cannot rebuild, and back it up with the secret store. Independent of the SAML signing credential, so rotating the credential changes no identifier. Generate with `openssl rand -hex 32`. |
| `AXIAM__AUTH__GDPR_PSEUDONYM_PEPPER` | HMAC-SHA256 pepper (32 bytes, hex) used to pseudonymize audit-log actor identities on GDPR erasure. Generate with `openssl rand -hex 32`. |
| `AXIAM__AUTH__PEPPER` | Server pepper (plain string). Prepended before Argon2id password hashing, **and** keys client-secret hashing (OBS-1). **Mandatory in a release build** — the server refuses to start without it. Generate a long random string, e.g. `openssl rand -base64 32`. |
| `AXIAM__AUTH__PEPPER_PREVIOUS` | Outgoing pepper, **verify-only**, set for the duration of a pepper rotation. Unset outside a rotation. See below. |

Set every value to a placeholder such as `<set-in-secret-manager>` in any
example or template you author — never commit real key material, and never
reuse the same value across environments.

### What a tenant's directory needs (LDAP / Active Directory)

Three things an operator must know before pointing AXIAM at a directory, then
[how a tenant administrator manages it](#managing-a-tenants-directory) (routes,
console, and what each action does), then what the address guard and the sync job
do:

- **A read-only bind account.** AXIAM binds as `bind_dn` only to search for the
  user signing in, then binds as that user to check the password. It never adds,
  modifies, deletes or changes a password in the directory. Give the account
  read rights on the user subtree (and, for group mapping later, the group
  subtree) and nothing else — on Active Directory an ordinary domain user with no
  extra privileges is enough. Its secret is encrypted at rest under
  `AXIAM__AUTH__DIRECTORY_ENCRYPTION_KEY` and never returned by any API.
- **Trust anchors.** The directory's server certificate is verified against the
  tenant's own `trust_anchors_pem` — the CA that issued it (your corporate CA,
  or the organization's AXIAM CA) — and it must name the host in the URL. Only an
  empty list means the public Mozilla roots; the two are never combined, and
  verification cannot be switched off. Use a hostname, not an IPv6 literal, in the
  URL: a bracketed address cannot be verified and fails closed. TLS 1.2 is the
  minimum.
- **Why plaintext is refused.** A directory bind carries the user's corporate
  password, which unlocks everything else the directory gates. `ldap://` is
  accepted only with StartTLS, and AXIAM sends nothing but the StartTLS request
  before the handshake completes; a server that refuses the upgrade receives no
  bind at all. Plain `ldap://` without StartTLS is refused when the configuration
  is saved, and again at every sign-in.

AXIAM's lockout applies in front of the directory, so set the tenant's
`max_failed_login_attempts` **below** the directory's own lockout threshold:
AXIAM then stops binding before the directory would lock the account.

**Checked against real servers.** The connector, the group mapper and the sync job
are exercised against a containerised OpenLDAP and a Samba Active Directory domain
controller by `crates/axiam-server/tests/directory_e2e.rs` (CI workflow
`directory-e2e.yml`); to run it yourself, or to see exactly what directory shape
it assumes, read [`docker/directory/README.md`](../../docker/directory/README.md).

#### Managing a tenant's directory

A tenant administrator configures the directory under
`/api/v1/tenants/{tenant_id}/directory` (OpenAPI tag `directory`, contract
[§30](../../sdks/CONTRACT.md)) or on the console's **Directory** page, which
sits with the tenant's other configuration pages. The caller's own tenant only:
another tenant's id is `403`. Three permissions, seeded like every other and held
by the `admin` and `super-admin` roles: `directory:read` (read the configuration
and the sync status), `directory:write` (create, replace, edit, delete) and
`directory:link` (link an account — kept apart because it acts on a person, not on
the configuration). A service-account token is refused on all of them: the bind
secret is a human administrator's to enter.

| Action | Route | Notes |
|---|---|---|
| read | `GET …/directory` | `404` until one is saved. The bind secret is never returned, and nothing says whether one is set. |
| create / replace | `PUT …/directory` | `201` or `200`. A replacement resets every member it omits to its default. |
| edit | `PATCH …/directory` | Sparse: only the members sent change; `null` clears `group_base_dn` or `group_filter`. |
| delete | `DELETE …/directory` | Removes the configuration and its sync state. See below. |
| link | `POST …/directory/links` | `{"user_id": …}`; see below. |
| sync status | `GET …/directory/sync-status` | Last result and times; the counts of what a run did are in its audit rows. |

**Every write is checked before anything is stored**: by the same validation the
sign-in path trusts (plaintext URL, userinfo, a filter without exactly one
`{username}`, an over-long secret, a trust anchor that is not a CA certificate, a
malformed or foreign-tenant group mapping, out-of-range depth or interval) and by
the address guard above, **on the URL as written** — so a name that was re-pointed
since the last save is caught by the next write that leaves the directory
**enabled**, even if the URL did not change. A write whose resulting configuration
is *disabled* skips the guard (a disabled directory opens no connection), so you
can always switch a directory off without deleting it; validation and the
secret-again rule still apply, and re-enabling runs the guard.
Each refusal is a `400` that names the rule and never echoes the secret. An
IPv6-literal URL is one of them: it can never be certificate-checked, so name the
directory by host name. One exception keeps the route from mapping your internal
DNS: for a host **name**, every refusal that depends on what the name resolved to —
it does not resolve, or resolves to loopback, link-local, the metadata service,
AXIAM's own listener or a private address outside
`AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS` — is the same message ("does not
resolve to an address this deployment permits") and the same audit rule,
`address_guard.not_permitted`. The specific reason is in AXIAM's log, as `a
directory write was refused by the address guard` with its `rule`. An IP literal's
refusal names its class. `DELETE` resolves nothing and always works.

**Moving the connection needs the secret again.** A write that changes `url`,
`start_tls`, `bind_dn` or `trust_anchors_pem` without a `bind_secret` is a `400`
(P23W2-01): a kept secret sent to a new host, through a trust anchor the editor
chose, is the secret handed to whoever runs that host. The console asks for the
secret again as soon as any of those four fields is edited, and the audit row
records that the connection moved. A write that leaves them alone — a filter, the
sync interval, enabling or disabling — needs no secret.

**A directory and `opaque_mode = required` never coexist.** Under `required` the
tenant refuses `/auth/login` before reading a password, so directory accounts could
not sign in. Saving an *enabled* directory under an effective `required` is `409`,
and so is a settings write (tenant, tenant override, or the organization baseline
for the tenants that inherit it) that would make `required` true for a tenant with
an enabled directory. A disabled configuration may coexist; enabling it is then
the refused write.

**Accounts whose entry has no usable e-mail address cannot be provisioned.** A
local account must have an e-mail address, and AXIAM does not invent one: a
placeholder would be released as the user's e-mail `NameID` and as the OIDC
`email` claim. With `jit_provisioning` on, a first sign-in for an entry whose
mapped e-mail attribute is missing, empty or unusable is the ordinary
invalid-credentials failure (the user sees nothing different from a wrong
password) and the audit log gets a `directory.jit_refused` row with the reason
`unusable_attributes`. Active Directory entries without `mail` are the usual
case: fill the attribute in the directory, or map `user_attribute_map.email` to
an attribute every entry has. The same applies to a username that is missing, too
long, or holds control or bidirectional-override characters.

**Guessing at names that have no account yet is locked out too.** With
`jit_provisioning` on, a sign-in for a name that matches no AXIAM account is
answered by the directory, so AXIAM counts the failures the directory decides (a
wrong password, or no such entry) per tenant and login name, ignoring case, with
the tenant's own lockout policy — the same threshold, duration and backoff an
account gets. Past the threshold the name is answered as an unknown user without
asking the directory, even with the right password, until the lockout expires; a
successful sign-in clears it. The count is kept in each server process's memory,
so with several replicas a name gets at most that many times the attempts per
window, and a restart forgets it. Set the tenant threshold below the directory's
own, as for accounts, so AXIAM's lockout engages first.

**Linking an existing local account** (`directory:link`). Just-in-time
provisioning only ever creates accounts, for login names that match no local
account — it never turns an existing account into a directory account, so a
directory administrator cannot take over a local `admin` by creating a matching
entry. Linking is the explicit act that does: the directory finds the entry from
the account's *own* username (you name only the account), the account is marked,
its password hash is replaced by one nobody holds, and everything it held that
authenticates without the directory deciding is retired — its passkeys and
security keys are deleted, its federation links (a social or upstream-IdP
identity bound to it) deleted, its `User`-type certificates revoked, and all its
sessions and OAuth2 refresh tokens revoked. TOTP is kept. **The owner is signed
out everywhere.** Linking an account that is already linked to that entry is `200`
with `was_already_linked: true` and repeats the revocations (the way an
interrupted link is completed); an entry linked to another account, an account
linked to a different entry, or a tenant with no enabled directory is `409`; no
single entry is `404`; the directory not answering is `503`. There is no unlink.

**Disabling or deleting a directory stops the directory, and only that.** Directory
accounts can no longer sign in with a password (there is no fallback to a local
hash) and the sync job stops for the tenant, so a later disable in the directory
no longer reaches AXIAM. Sessions, refresh tokens and passkeys those accounts
already hold keep working until they expire or an administrator deactivates the
accounts. The audit row (`directory.config_updated` with `enabled` false, or
`directory.config_deleted`) records how many live directory accounts the tenant
had, so you can see what was left behind.

**Audit.** `directory.config_created`, `directory.config_updated` and
`directory.config_deleted` carry the actor, the **names** of the fields that
changed, `connection_moved`, `secret_replaced` and, on a delete or disable, the
count of live directory accounts. A refused write that names an address-guard or
P23W2-01 rule is audited too, with the `rule`. No row ever carries the secret or
the content of a trust anchor.

**Without `AXIAM__AUTH__DIRECTORY_ENCRYPTION_KEY`** the feature is unavailable: a
write that carries a bind secret is `503`; reading, deleting and the sync status
still work, and so does a write that carries no secret (for example switching a
directory off).

#### Where a directory may be: the address guard and the frame cap

A tenant administrator chooses the directory URL, so the connector holds every
directory host to a rule **you** set, before it opens a socket (T23.3.7, closes
T-300). The host is resolved and **every** address it resolves to must pass:

| Address | Answer |
|---|---|
| globally routable | admitted |
| loopback (`127.0.0.0/8`, `::1`), unspecified (`0.0.0.0/8`, `::`), link-local (`169.254.0.0/16` — the cloud metadata service — and `fe80::/10`), multicast, documentation / benchmarking / reserved and the other special-purpose blocks | **always refused** |
| private — RFC 1918, CGNAT `100.64.0.0/10`, IPv6 unique-local `fc00::/7` | refused **unless** inside a network in `AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS` |
| a metadata endpoint inside a private range (`fd00:ec2::254`, `100.100.100.200`) | refused whatever the list says |
| an address of this host on AXIAM's REST or gRPC port | refused |

IPv4-mapped IPv6 answers are judged as the IPv4 address they carry. An
IPv6-literal URL is refused (no certificate can be checked against it); name
the directory by a host name. The connection is then **pinned**: the TCP socket
goes to the address that was checked, nothing resolves the name a second time,
and the certificate is still verified against the URL's host name. The check
runs again at every connection — sign-in, group lookup, the sync job — so a
name re-pointed after the configuration was saved is caught at the next one.

- **`AXIAM__DIRECTORY__ALLOWED_PRIVATE_NETWORKS`** — comma-separated CIDR blocks
  (or single addresses). Unset, no private address is admitted and only a
  directory on a public address works. Corporate directories live on private
  networks, so a deployment offering the feature normally sets this to the
  networks its domain controllers or LDAP servers are in. **Do not list the
  network AXIAM's own pods, services or load balancers are in**: the listener
  rule recognises this host's own addresses only, not another replica's pod IP
  or a Service address that forwards back to AXIAM. Inside a listed network any
  tenant administrator can aim the connector at any host and port; what that
  buys is a TLS handshake (or one StartTLS request) toward a host that must then
  present a certificate chaining to that tenant's anchors before anything else
  is sent, answered to the user as the generic sign-in failure. An entry that
  does not parse is ignored and logged at `error` — a typo admits nothing.
- **`AXIAM__DIRECTORY__MAX_MESSAGE_BYTES`** — the frame cap: the largest LDAP
  message accepted from a directory, default 2 MiB, clamped to 64 KiB … 16 MiB.
  Every message a directory sends is measured and its structure checked before
  the LDAP library sees it; a longer declared length, an indefinite length,
  nesting deeper than 16 levels or a message without an id and an operation ends
  the connection on the spot, with a `warn` line naming the reason. Without it a
  hostile directory could make the connector — which every tenant shares —
  buffer whatever it sent, or crash its parser. Raise the cap only if an
  ordinary answer is refused.

A refused address shows up as the generic sign-in failure for the user and a
`warn` line for you (`directory authentication could not be performed`, with
the rule in `reason`); saving such a URL is refused with a `400` naming the rule,
and the refusal is written to the audit log with the rule (never the secret).

#### Sync: what the job disables, and what it never does

A background job on the server's cleanup scheduler (job name `directory_sync` in
`GET /health/jobs`) keeps AXIAM's directory accounts in step with the directory,
one tenant at a time, for tenants whose directory is **enabled**. It is
read-only against the directory and **cannot grant anything**.

- **What it disables.** An account whose entry has **vanished** from the
  directory (not found by its immutable identifier under `base_dn`, or moved out
  of `base_dn`) or that the directory has **disabled** is set `Inactive`: its
  sessions and OAuth2 refresh tokens are revoked, the group memberships the
  directory mapping gave it are removed (memberships an administrator added by
  hand are kept), and from then on nothing authenticates it — passkeys and the
  browser single sign-on cookie included. *Disabled* means `userAccountControl`
  bit `0x2` on Active Directory and, on OpenLDAP, `pwdAccountLockedTime` equal to
  the `ppolicy` overlay's **permanent-lock value** `000001010000Z`. Any other
  value — a past or future time, which is what a temporary lockout after failed
  attempts writes — is **not** a disable: someone guessing passwords against the
  directory could otherwise deactivate accounts permanently, because nothing
  re-enables them. The row, its directory marker and its
  audit trail stay: sync never hard-deletes and never marks an account
  `Deleted`. Erasure under GDPR remains an explicit administrator action.
- **Nothing re-enables.** If the directory enables an account again, or an entry
  reappears, the account **stays `Inactive`**; the audit log gets one
  `directory.account_reappeared` row ("administrator action required") and an
  administrator re-enables the account if that is right. Sync also never creates
  an account and never links one by name; it acts only on accounts that already
  carry a directory marker. It keeps a present, enabled account's username, email
  and display name in step with its entry (a change that would collide with
  another account is skipped and audited, never applied) and applies the group
  mapping.
- **Two kinds of run.** An *incremental* run every `sync_interval_secs` (5
  minutes to 24 hours; the scheduler ticks every `cleanup_interval_secs`, 5
  minutes by default) asks for entries changed since a stored watermark —
  `modifyTimestamp` on OpenLDAP, `uSNChanged` on Active Directory, where the
  watermark is `highestCommittedUSN` read from the rootDSE of the same domain
  controller. A *full* run every 24 hours (and first, and after any run that
  skipped an account, hit a bound, or could not trust its watermark) looks up
  **every** directory account by `entryUUID` / `objectGUID`. Only a full run
  concludes that an entry has vanished. If the Active Directory server your URL
  reaches changes (a different `dsServiceName`, as behind a load balancer) or the
  rootDSE gives no watermark, the run is a full one; on such a setup point the
  URL at one domain controller to keep runs incremental.
- **The safety valve.** A full run that would deactivate **more than 10 %** of
  the tenant's directory accounts **and at least 5** of them applies nothing at
  all, writes `directory.sync_safety_valve` once, and shows as a failure of
  `directory_sync` in `GET /health/jobs`. An empty search after a
  misconfiguration, a wrong `base_dn` or an outage must not disable a company.
  The run is retried at each interval and stays blocked until the directory is
  fixed or the accounts that are really gone are deactivated by hand.
- **Failure changes nothing.** A directory that cannot be reached, a refused
  search or a deadline ends that tenant's run before anything is written, and
  records the failure; the other tenants still run. An unreadable question — an
  identifier that is not a GUID, two entries with one identifier — skips that
  account and is never read as "vanished".
- **Rights the bind account needs, beyond reading the users.** It must be able
  to read, on the user subtree, the identifier (`entryUUID` / `objectGUID`), the
  attributes you mapped, the change attribute (`modifyTimestamp` / `uSNChanged`)
  and the disabled attribute (`pwdAccountLockedTime` / `userAccountControl`),
  and on Active Directory the rootDSE (`highestCommittedUSN`, `dsServiceName`).
  OpenLDAP's `modifyTimestamp` and `pwdAccountLockedTime` are operational
  attributes: grant `read` on them explicitly if your ACLs hide them. An
  attribute the account cannot read is treated as absent: it never disables an
  account, and without a readable change attribute every run is a full one.
- **No multi-replica guard.** Every replica runs the job. Each write is
  idempotent or a compare-and-set, so the outcome is the same; the cost is
  duplicate directory reads and, for attribute and group changes, duplicate
  audit rows. Run it on one replica (or accept the duplication) if the directory
  is small or slow.

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

## Recovering the bootstrap setup token

On a deployment that has **not** been bootstrapped yet, an operator who lost
the one-time setup token from the first-boot log can mint a new one:

```
axiam-server setup-token --remint
```

The token is printed to stdout and nowhere else. The command refuses with exit
code `2` once the deployment has any user or any redeemed setup token — see
[the bootstrap section of the administration guide](../admin/README.md#i-lost-the-setup-token)
for the gate and what to do when it refuses.

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
| `AXIAM__RATE_LIMIT__TOKEN_PER_MIN` | Max `/oauth2/token` requests per minute per key (default `120`). Also the allowance of the second, narrower bucket a token request carrying **no client credential** is counted in, which is always keyed on `client_id` and the transport peer address together — see [Public clients](../admin/public-clients.md#rate-limiting). |
| `AXIAM__RATE_LIMIT__PASSWORD_RESET_PER_MIN` | Max password-reset requests per minute per key (default `3`). |
| `AXIAM__RATE_LIMIT__MFA_PER_MIN` | Max MFA enroll/confirm/verify requests per minute per key (default `5`). |
| `AXIAM__RATE_LIMIT__WEBAUTHN_PER_MIN` | Max WebAuthn ceremony requests per minute per key (default `10`). Applies to each of the six `/auth/webauthn/*` routes independently, so it is the per-minute ceremony allowance — deliberately equal to `LOGIN_PER_MIN`. |
| `AXIAM__RATE_LIMIT__INTROSPECT_PER_MIN` | Max `/oauth2/introspect` requests per minute per key (default `600`). |
| `AXIAM__RATE_LIMIT__REVOKE_PER_MIN` | Max `/oauth2/revoke` requests per minute per key (default `60`). |
| `AXIAM__RATE_LIMIT__AUTHZ_CHECK_PER_MIN` | Max authz-check requests per minute per key (default `1800`). |
| `AXIAM__RATE_LIMIT__DEVICE_LOGIN_PER_MIN` | Max `POST /api/v1/auth/device` (device mTLS login) requests per minute per IP (default `60`). The route carried no limiter at all before 1.0.0-beta17, although a TLS handshake bearing a client certificate is the most expensive thing an unauthenticated caller can ask of the server. Sized from the honest traffic rather than from capacity: a device re-authenticates once per access-token lifetime (900 s by default), so 60/min holds a fleet of nine hundred devices on one address. Part of the machine family, so `AXIAM__RATE_LIMIT__PROFILE` scales it — which is what a fleet behind a single NAT should reach for. |
| `AXIAM__RATE_LIMIT__DEVICE_AUTHORIZATION_PER_MIN` | Max `/oauth2/device_authorization` requests per minute per IP (default `12`). |
| `AXIAM__RATE_LIMIT__BC_AUTHORIZE_PER_MIN` | Max CIBA backchannel authentication requests (`POST /oauth2/bc-authorize`) per minute (default `60`), in a bucket of its own keyed like `/oauth2/token` (`AXIAM__RATE_LIMIT__KEY` applies), plus a per-client bucket of the same size after authentication. Scaled by `AXIAM__RATE_LIMIT__PROFILE` (`gateway` 600, `mesh` 6000). Each user is sent at most three CIBA notifications a minute whatever this is set to. |
| `AXIAM__RATE_LIMIT__DEVICE_VERIFY_PER_MIN` | Max `/api/v1/device/verify` + `/device/decide` requests per minute per IP (default `10`). Bounded by the user-code brute-force assertion in `RateLimitConfig::validate`. |
| `AXIAM__RATE_LIMIT__DCR_PER_MIN` | Max `POST /oauth2/register` (RFC 7591 dynamic client registration) requests per minute per IP (default `5` — the smallest limit in AXIAM). It is the only endpoint that **writes** for a caller holding no credential, and every accepted request allocates a client row that counts against the tenant's `dcr_max_clients`, so the thing being limited is an anonymous party's ability to fill a tenant's client table — not throughput. The honest traffic is one person registering one MCP client once. Never moved by `AXIAM__RATE_LIMIT__PROFILE`. See [`docs/admin/dynamic-client-registration.md`](../admin/dynamic-client-registration.md). |
| `AXIAM__RATE_LIMIT__DIRECTORY_ADMIN_PER_MIN` | Max writes per minute per IP to the tenant directory management API — `PUT`, `PATCH`, `DELETE` on `/api/v1/tenants/{tenant_id}/directory` and `POST …/directory/links` (default `30`). Each write resolves a tenant-chosen host name (the address guard), and linking opens directory connections, so the limit bounds how fast an administrator, or a stolen administrator token, can use the routes as a resolver. One bucket per route: the configuration resource's three methods share one, the link route has its own. Reads are not limited. Never moved by `AXIAM__RATE_LIMIT__PROFILE`. See [Managing a tenant's directory](#managing-a-tenants-directory). |
| `AXIAM__RATE_LIMIT__SAML_ADMIN_PER_MIN` | Max writes per minute per IP to the SAML service-provider registry API — create, update and delete a service provider, `POST …/saml/parse-sp-metadata`, and issue, promote and retire the IdP signing credential under `/api/v1/tenants/{tenant_id}/saml` (default `30`). Issuing generates an RSA-4096 key and parsing metadata makes an outbound request, so the limit bounds how fast an administrator, or a stolen administrator token, can burn CPU, use the server to reach an external host, or rewrite where assertions go. One bucket per route; reads are not limited. Never moved by `AXIAM__RATE_LIMIT__PROFILE`. |
| `AXIAM__RATE_LIMIT__SSF_PER_MIN` | Max requests per minute per IP to each route of the Shared Signals Framework receiver surface — `/ssf/v1/stream`, `/ssf/v1/status`, `/ssf/v1/verify`, `/ssf/v1/poll/{stream_id}` (RFC 8936, whose long poll holds a request for up to 30 s) and both `/.well-known/ssf-configuration` forms (default `60`). One bucket per route, checked before the receiver's token. Each stream also enforces a 60-second `min_verification_interval` of its own (`429`). Never moved by `AXIAM__RATE_LIMIT__PROFILE`. |
| `AXIAM__RATE_LIMIT__SSF_ADMIN_PER_MIN` | Max writes per minute per IP to the SSF stream registry's management API — create, update and delete under `/api/v1/tenants/{tenant_id}/ssf/streams` (default `30`). Each write can repoint where a tenant's security events and the push credential go. One bucket per route; reads are not limited. Never moved by `AXIAM__RATE_LIMIT__PROFILE`. |
| `AXIAM__RATE_LIMIT__SCIM_TARGET_ADMIN_PER_MIN` | Max writes per minute per IP to the outbound SCIM target registry's management API — create, update, delete and reconcile now under `/api/v1/scim-targets` (default `30`). Each write can repoint where a tenant's user directory and the target's credential go. One bucket per route; reads are not limited. Never moved by `AXIAM__RATE_LIMIT__PROFILE`. |
| `AXIAM__RATE_LIMIT__CIBA_APPROVAL_PER_MIN` | Max requests per minute per IP to each CIBA approval route — `GET /api/v1/ciba/requests` (the pending list), `GET /api/v1/ciba/requests/{id}`, `POST …/approve`, `POST …/deny` (default `30`). One bucket per route, so reads cannot starve decisions. Human-driven and behind a session and CSRF token; every request id that is not the caller's own answers `404`. Never moved by `AXIAM__RATE_LIMIT__PROFILE`. |
| `AXIAM__RATE_LIMIT__SCIM_PER_MIN` | Max `/scim/v2/*` requests per minute per IP (default `600`). One bucket spans the whole SCIM surface — Users, Groups and the discovery endpoints, reads and writes alike. Sized as the REST twin of `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` (also 600/min): a privileged M2M provisioning client whose real cost is Argon2id. Never moved by `AXIAM__RATE_LIMIT__PROFILE`. |
| `AXIAM__RATE_LIMIT__TRUSTED_HOPS` | Number of trusted reverse-proxy **entries** to skip from the right of `X-Forwarded-For` when deriving the client IP (default `0`). It is **the number of proxies in front of the server minus one** — see [Deriving `TRUSTED_HOPS`](#deriving-trusted_hops) before setting it. Both shipped topologies have exactly one proxy, so `0` is correct for them. |
| `AXIAM__RATE_LIMIT__KEY` | Bucket-key derivation mode: `ip` (default) \| `client_id` \| `ip_client_id`. See below. |
| `AXIAM__RATE_LIMIT__PROFILE` | Deployment posture preset: `internet` (default — the shipped values above, unchanged) \| `gateway` \| `mesh`. Sets the machine-traffic family (key mode, token/introspect/revoke/authz, device login, and the gRPC authz ceiling) coherently in one variable; never changes the human endpoints. See [Sizing your rate limits](rate-limit-sizing.md). |
| `AXIAM__RATE_LIMIT__SHARED` | Enables (`on`, default) or disables (`off`) the cross-replica shared counter. `off` is a **single-replica escape hatch**: it skips the shared layer entirely (no state, no store call, no flusher) and leaves the per-replica in-memory `Governor` as the sole limiter. Do not set `off` behind an HPA/multiple replicas — it re-opens the N× effective-limit multiplication the shared counter exists to close. |
| `AXIAM__RATE_LIMIT__SHARED_SYNC_MS` | Write-behind flush interval for the shared counter, in milliseconds (default `1000`, clamped `50`–`60000`). Directly scales the cross-replica overshoot bound — see [Shared-store consistency model](#shared-store-consistency-model-write-behind) below. |

The gRPC listener has its own per-second ceilings, one bucket per gRPC
**method family** (reflection and health share a fixed, deliberately
generous 100/s bucket):

| Key | Purpose |
|---|---|
| `AXIAM__GRPC__GRPC_AUTHZ_PER_SEC` | Max `axiam.v1.AuthorizationService` requests per second per IP (default `100`). |
| `AXIAM__GRPC__GRPC_IDENTITY_PER_SEC` | Max `axiam.v1.UserInfoService` + `axiam.v1.TokenService` requests per second per IP. Unset = 5x the authz ceiling (default `500`). |
| `AXIAM__GRPC__GRPC_ADMIN_PER_SEC` | Max `axiam.v1.UserService` + `axiam.v1.ReactorAdminService` requests per second per IP. Unset = a flat `10` (600/min per IP) in **every** posture — `ValidateCredentials` is Argon2id-bound, so this is a CPU guard on online password guessing and is deliberately not derived from the read-sized authz ceiling (SEC-079). `ReactorAdminService` joined this family in beta12: it is administrative traffic and should not be sized from, or raised with, authorization throughput. |
| `AXIAM__GRPC__KEY` | Reserved for D8 parity; currently a no-op (the gRPC limiters are always per-IP — see [Sizing your rate limits § 5](rate-limit-sizing.md)). |

> **Which numbers should you actually run?** See
> **[Sizing your rate limits](rate-limit-sizing.md)** — the measured hardware
> envelope, the `gateway`/`mesh` presets, how to size by hand, and the
> security caveats that come with per-client keying. The shipped defaults are
> tuned for a small internet-facing deployment and are known to be too strict
> for a NAT'd M2M fleet.

### Deriving `TRUSTED_HOPS`

Get this wrong and per-IP limiting silently stops working — in the direction
that hurts, since every client collapses into one bucket and one attacker's
flood exhausts the allowance everybody shares. `/auth/login` is keyed per-IP and
never per-principal precisely so that an attacker cannot lock a victim out;
collapsed, it does exactly that.

The rule follows from one fact about how proxies write the header:

> A proxy appends **the address it received the request from**, not its own.
> nginx's `proxy_add_x_forwarded_for` is `$http_x_forwarded_for, $remote_addr`;
> Caddy's `reverse_proxy` and ingress-nginx behave identically.

So the **nearest** proxy never appears in the header the server reads — it is
the socket peer. Therefore:

> **`TRUSTED_HOPS` = (number of reverse proxies between the client and the
> server) − 1**, i.e. the number of *proxy* addresses that actually appear in
> the `X-Forwarded-For` the server receives.

| Topology | Header the server sees | Value |
|---|---|---|
| Direct, no proxy | *(absent)* → `peer_addr()` | `0` |
| `k8s/ingress.yml` — ingress-nginx → server | `<client>` | **`0`** |
| Compose/Pi — Caddy → server | `<client>` | **`0`** |
| Caddy → frontend nginx → server | `<client>, <caddy>` | **`1`** |
| CDN → ingress → server | `<client>, <cdn-edge>` | **`1`** |
| Cloud L7 LB → ingress → mesh sidecar → server | `<client>, <lb>, <ingress>` | **`2`** |

Behind exactly one appending proxy, `0` selects the real client **whether or not
the client sends a forged `X-Forwarded-For`** — the proxy appends the real peer
to the right of the forgery and the extractor reads from the right. That
property is why `0` is the shipped default rather than merely a convenient one.

Setting the value to the proxy *count* instead makes
`trusted_hops >= hops.len()`; the extractor then discards the header entirely
and keys on `peer_addr()` — the proxy's own address. Earlier revisions of this
document advised exactly that, and it produced the failure the extractor exists
to prevent. Both shipped topologies now set the value explicitly
(`docker-compose.prod.yml`, `k8s/server/configmap.yml`) with the derivation in a
comment, because a value that is correct by accident is one nobody re-derives
when they add a load balancer.

**Verify it rather than trusting it.** From two source addresses on different
networks, hammer a per-IP endpoint past its budget. If the second address is
throttled the moment the first is, the value is wrong.

**And since beta12, the server tells you.** Two things changed, because "get
this wrong and per-IP limiting silently stops working" had *silently* doing a
lot of work:

1. **A boot line states the value and the rule together**, next to the
   rate-limit posture it shapes, so the number can be checked against your own
   topology before any traffic arrives:

   ```
   INFO Rate-limit client-IP derivation: X-Forwarded-For is trusted for 0
        appended hop(s), i.e. this server expects 1 proxy/proxies in front of it.
        trusted_hops=0 rule="trusted_hops = proxies - 1" implies_proxies=1
   ```

2. **A discarded header is counted and warned about.** When a header is present
   but `trusted_hops` discards it, the first occurrence logs one `WARN` naming
   the hop count seen, the value in force and the rule, and every occurrence
   increments
   `axiam_rate_limit_xff_discarded_total{protocol="rest"|"grpc"}`.

   A non-zero counter is not automatically a fault — a client sending its own
   `X-Forwarded-For` to a server that correctly ignores it lands here too. It
   **is** a fault when the counter tracks total request volume: that means the
   header is discarded on every request, so every client is keying on the
   proxy's address and the whole deployment shares one bucket. That is the
   failure this section describes, and it is now visible on a dashboard rather
   than only in an incident. The `WARN` is once per process, because the
   condition fires on every request and one line each would be a log flood
   proportional to traffic.

   Both listeners read the same variable and emit the same signal under their
   own `protocol` label, so a discrepancy between the two is a bug in this
   server, not in your topology.

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

**1. Proxy-terminated TLS (the default).** The server binds plaintext
on `:8090` and an ingress controller / load balancer / reverse proxy terminates
TLS in front of it (this is how the Kubernetes manifests and
`docker-compose.prod.yml` are wired out of the box — see the ingress
`TLS secretName` at the top of this document). Configure the proxy to require
TLS 1.3, e.g. for Nginx:

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

| `AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS` | How often to re-read the pair and pick up a renewal, in seconds (default `3600`, `0` disables). |
| `AXIAM__SERVER__TLS__CLIENT_AUTH` | Native client-certificate policy: `off` (default), `optional`, `required`. |
| `AXIAM__SERVER__TLS__CLIENT_CA_PATH` | PEM bundle used to verify client certificates. Required when `CLIENT_AUTH` is not `off`. |

When `ENABLED` is `true`, both paths are mandatory and must point at readable,
well-formed PEM files — the server **fails fast at startup** (it never falls back
to plaintext) on a missing path, an unreadable/malformed file, an empty
certificate chain, or a certificate/key mismatch. Mount the cert and key as
secret volumes; never commit key material to git.

**Certificate renewal.** rustls resolves the certificate per handshake but reads
nothing from disk, so without help the leaf a server boots with is the leaf it
serves forever — which matters the moment an ACME client is involved, since
Let's Encrypt issues for 90 days and renews at 60. AXIAM re-reads the pair on
**`SIGHUP`** and on the `RELOAD_INTERVAL_SECS` poll, and installs it behind a
slot rustls consults per handshake: the next connection uses the new
certificate, with no restart and no dropped request.

Send `SIGHUP` from your ACME deploy hook; that is immediate. The poll is the
safety net for the case that actually happens — a hook nobody wired up, or a
runtime that does not forward signals — and re-reading two small files an hour
costs nothing. The comparison is on the parsed certificate chain rather than on
file metadata, because an mtime can change without the certificate changing and
can fail to change when it does. A reload that finds an unreadable or mismatched pair (certbot writes
the chain and the key as two separate operations, so a poll will occasionally
catch one mid-write) logs a warning, **leaves the previous certificate
serving**, and retries on the next tick.

**3. Both, on one listener.** Terminating TLS in the server does not mean giving
up an edge proxy. The topology
[`claude_dev/public-backend-tls-design.md`](../../claude_dev/public-backend-tls-design.md)
documents — and that the Raspberry Pi runbook builds — keeps a proxy at the
public port routing by path, and has it speak **TLS to the backend** rather than
cleartext:

```
client ──443/TLS──> edge ──┬── /                            ──> frontend (SPA)
                           └── /api, /oauth2, /.well-known ──TLS──> axiam-server
```

That is the same path split `k8s/ingress.yml` has always used. The gain over
pattern 1 is that no password, bearer token or session cookie crosses the
internal network in cleartext, and the gain over routing everything through the
frontend's nginx is one fewer hop — which is also what makes `TRUSTED_HOPS = 0`
correct (see [Deriving `TRUSTED_HOPS`](#deriving-trusted_hops)).

`docker/nginx.conf.template` renders the frontend's upstream from
`AXIAM_BACKEND_ORIGIN` / `AXIAM_BACKEND_SNI` / `AXIAM_BACKEND_CA`, so the same
image talks to a plaintext backend (dev, E2E) or a TLS one. Certificate
verification is **always on** in every rendering and there is deliberately no
setting that disables it — a backend certificate that does not verify is a
misconfiguration to fix.

#### The console resolves the backend per request

The console's nginx looks up the host in `AXIAM_BACKEND_ORIGIN` when a request
needs it, not once at startup, and reuses an answer for at most 30 seconds. So
the console starts whether or not `axiam-server` exists yet — `/api`, `/oauth2/`
and `/.well-known` answer `502` until it does, then `200`, with no restart — and
a backend recreated on a new address is picked up within the same 30 seconds.
Through 1.0.0-beta16 a console started ahead of its backend exited at once with
`host not found in upstream`, and one whose backend was recreated answered
`502` until it was restarted too.

| Variable | Default | Meaning |
|---|---|---|
| `AXIAM_BACKEND_RESOLVER` | the `nameserver` lines of the container's `/etc/resolv.conf` | DNS server(s) nginx asks, as nginx's [`resolver`](https://nginx.org/en/docs/http/ngx_http_core_module.html#resolver) takes them: `10.96.0.10`, `127.0.0.11:53`, `[fd00::53]`, space-separated for several |

Leave it unset on Docker and on Kubernetes: the container's own `resolv.conf`
already names the right server — Docker's embedded DNS at `127.0.0.11` on a
user-defined network, the cluster DNS Service (the `kube-dns` ClusterIP) on
Kubernetes. Set it when neither is what you want, for example a node-local DNS
cache.

Two rules follow from nginx doing its own lookups:

- **The origin is `scheme://host:port` and nothing else** — no path and no
  trailing slash. With a path, nginx would send every request to that path
  rather than to the one the client asked for.
- **The host must resolve exactly as written.** nginx's resolver does not apply
  `resolv.conf`'s `search` domains. Docker's embedded DNS answers a bare service
  name such as `axiam-server`, so the default origin works under Compose. On
  Kubernetes, write the fully qualified Service name:
  `http://axiam-server.axiam.svc.cluster.local:8090`. A bare name there answers
  `502` for every proxied request. The console still starts, but the error log
  records `could not be resolved`.

An `https` origin is verified exactly as before: the certificate is checked
against `AXIAM_BACKEND_SNI`, never against whatever address the lookup returned,
so a wrong DNS answer fails the handshake rather than reaching a different
server.

### The gRPC listener: TLS and client certificates

The gRPC listener (`:50051`) terminates TLS itself when both of its certificate
variables are set, with the same TLS 1.3-only posture and the same reloadable
leaf as the REST listener. Point them at the REST pair and one `SIGHUP` renews
both. It can also verify client certificates, **off by default**:

| Key | Purpose |
|---|---|
| `AXIAM__GRPC_TLS_CERT_PATH` | PEM certificate chain. Both this and the key, or gRPC serves plaintext. |
| `AXIAM__GRPC_TLS_KEY_PATH` | Its private key. |
| `AXIAM__GRPC_TLS_CLIENT_AUTH` | `off` (default), `optional` or `required`. |
| `AXIAM__GRPC_TLS_CLIENT_CA_PATH` | PEM bundle client certificates are verified against. Required unless `CLIENT_AUTH` is `off`. |

The names are **flat** (single underscore after `AXIAM`), like the two
certificate variables. The nested spelling is not read.

- **`off`** is the listener as it has always been: no client certificate is
  requested, and one a client holds is never sent. A certificate-bound token
  (`cnf.x5t#S256`, which every device token issued over native mTLS carries —
  see [`docs/pki/README.md`](../pki/README.md)) is
  therefore **refused** on gRPC under `off`, because there is no certificate to
  match it against.
- **`optional`** asks for a certificate and verifies any that is presented. A
  client that presents none is still served on its token alone.
- **`required`** refuses the TLS handshake unless the client presents a
  certificate that chains to the bundle. No RPC runs before that check, so this
  is a network-level gate on the whole listener, including
  `ReactorAdminService`.

A verified certificate reaches the auth interceptor. There, a token bound to a
certificate is accepted only over a connection presenting **that** certificate.
The certificate is proof of possession and a gate. It is **not** an identity:
every call still needs a bearer token, and the token decides who the caller is.
`optional_self_signed` is refused on this listener. It exists for RFC 8705
self-signed OAuth2 clients, and the token endpoint they use is not served here.

**Boot is refused, not warned about**, when:

- `CLIENT_AUTH` is not one of the three words;
- `CLIENT_AUTH` is `optional` or `required` but `CLIENT_CA_PATH` is unset;
- `CLIENT_CA_PATH` is set but `CLIENT_AUTH` is `off`;
- the bundle is unreadable, unparsable or empty;
- either client-auth variable is set while the listener is **plaintext**
  (neither certificate variable set, or only one of them).

The last case is a refusal because the operator's intent is unambiguous. A
listener with no handshake cannot ask for a certificate, and serving cleartext
on a port its operator believes is mutually authenticated is the worst outcome
available. An explicit `CLIENT_AUTH=off` is accepted everywhere, and an empty
value counts as unset.

**One anchor set, one reload.** Point `AXIAM__GRPC_TLS_CLIENT_CA_PATH` at the
bundle the REST listener uses: `AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH`, or
`client-ca-bundle.pem` beside `AXIAM__SERVER__TLS__CERT_PATH`. The two
listeners then trust the same CAs. Flagging or unflagging a CA as an mTLS trust
anchor in the admin console rewrites that file and reloads **both** listeners
without a restart. The gRPC listener has its own verifier, because its policy
can differ from REST's (for example REST `optional` for browsers and gRPC
`required` for the mesh). On each reload it re-reads its own bundle, so it never
trusts a set that its next boot would not read. A reload that finds that file
unreadable or empty logs an error and **keeps the previous anchors**; it never
falls back to asking for nothing. If the gRPC bundle is a separate file you
curate yourself, a reload re-reads it and nothing else changes.

### Client certificates through a proxy

`AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT` (default **`false`**) controls whether
an `X-Client-Certificate` header is accepted as device identity when the
connection carries no TLS-verified client certificate.

Leave it off unless all three of these hold:

1. TLS and the client-certificate handshake terminate at a proxy you operate;
2. that proxy sets `X-Client-Certificate` from the certificate **it** verified,
   on every request, overwriting whatever the client sent;
3. nothing else can reach the server's listener.

The reason it is off by default: a certificate is public data, and the header
path checks the fingerprint, status, expiry and chain — every one of which a
*copy* of an enrolled device's certificate also satisfies. Only a TLS handshake
proves possession of the private key, and on that path there was none. So the
header authenticates whoever can set it. Where the server is reachable by
anything but that proxy, that is an authentication bypass.

**Native mTLS is unaffected and always preferred.** When rustls verified a
client certificate on the connection, that certificate is authoritative and this
setting is never consulted. If you have IoT devices and an edge that terminates
TLS, give the devices a route that is *not* terminated — a TCP-passthrough
Service, or a second hostname — rather than turning this on.

## Container healthcheck (`axiam-server healthcheck`)

The production image is distroless and has no shell, so `docker-compose.prod.yml`
probes it with the binary's own subcommand:

```yaml
healthcheck:
  test: ["CMD", "/usr/local/bin/axiam-server", "healthcheck"]
```

It requests `/health` and exits `0` on a 2xx, `1` otherwise. **The scheme
follows the listener**: `https` when the server terminates TLS itself
(`AXIAM__SERVER__TLS__ENABLED=true` *and* a certificate path set), `http`
otherwise, on `AXIAM__SERVER__PORT` (default `8090`). A proxy-terminated
deployment therefore needs no configuration at all, and neither does a
direct-TLS deployment whose certificate covers `127.0.0.1` — see below.

| Variable | Meaning |
|---|---|
| `AXIAM_HEALTHCHECK_URL` | Probe this URL instead of the derived default. Wins outright. |
| `AXIAM_HEALTHCHECK_CA_FILE` | PEM bundle whose certificates are added as trust anchors for the probe. |

**Note the single underscore**: both are read with `std::env::var` rather than
through the configuration layer.

**Where the trust anchors come from, when you set no CA file.** On a direct-TLS
deployment the probe trusts the server's own
`AXIAM__SERVER__TLS__CERT_PATH` chain file. A process verifying the certificate
it is itself serving gains no trust it does not already have, which is what
makes the default zero-configuration. Two cases follow from what that file
contains:

- a **self-signed** server certificate works on its own — an end-entity
  certificate that is its own issuer is a usable trust anchor (verified, not
  assumed: `crates/axiam-server/tests/healthcheck.rs`);
- a **CA-issued leaf** works when the file is a `fullchain.pem` that also holds
  the issuer. A file holding the leaf **alone** does not, because the issuer is
  then anchored nowhere — set `AXIAM_HEALTHCHECK_CA_FILE` to the issuing CA.

**The certificate has to cover the address probed.** The derived default is
`https://127.0.0.1:<port>/health`, so the certificate needs an IP SAN for
`127.0.0.1`. If it carries a DNS name instead, point the probe at that name with
`AXIAM_HEALTHCHECK_URL` and make the name resolve inside the container.

**There is no switch that skips verification, deliberately.** A probe that
accepted any certificate would report "healthy" for anything listening on the
port, which is worse than no probe at all — because a deployment then stops
looking. If the probe cannot verify the listener, it is not healthy, and the
reason goes to stderr, where `docker inspect` and `kubectl describe` surface it.

The Kubernetes manifests do not use this subcommand: `k8s/server/deployment.yml`
uses `httpGet` probes with `scheme: HTTPS`, which the kubelet performs without
verifying the certificate, from outside the container.

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
| [`allow-ingress-to-rabbitmq.yml`](../../k8s/network-policy/allow-ingress-to-rabbitmq.yml) | Restricts RabbitMQ (`5671`) ingress to pods labeled `component: server` only. |
| [`allow-ingress-to-surrealdb.yml`](../../k8s/network-policy/allow-ingress-to-surrealdb.yml) | Restricts SurrealDB (`8000`) ingress to pods labeled `component: server` only. |
| [`allow-ingress-to-vault.yml`](../../k8s/network-policy/allow-ingress-to-vault.yml) | Restricts Vault (`8200`) ingress to pods labeled `component: server` only. Required whenever `AXIAM__AUTH__SECRET_PROVIDER` is `vault` or CA signing keys are held in Vault; `kubectl port-forward` bypasses the pod network and is unaffected. |
| [`server-egress.yml`](../../k8s/network-policy/server-egress.yml) | Allows `axiam-server` to reach SurrealDB (`8000`), RabbitMQ (`5671`), Vault (`8200`), external HTTPS on `443` (OIDC JWKS, SAML IdPs, email APIs — RFC1918/CGN ranges and the cluster's pod/service CIDRs are explicitly excluded to prevent lateral movement), and an operator-configured SMTP relay on `25`/`465`/`587`. The SMTP rule ships pointed at a placeholder RFC 5737 TEST-NET-1 CIDR (`192.0.2.0/24`) — mail will not send until the operator replaces it with their real relay's CIDR; **never widen this to `0.0.0.0/0`**. |

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

### You MUST pin TLS 1.3 on the broker (SEC-106)

AXIAM's stated standard is TLS 1.3 minimum for all external communication, and
the broker link is external by design — six SDKs consume it directly. **The
AXIAM client cannot enforce that floor**, and this is a dependency limitation
rather than an oversight: lapin's only TLS-carrying entry point takes an
`OwnedTLSConfig` with exactly two fields (an identity and a certificate chain)
and no seam for a rustls `ClientConfig`, so there is nowhere to set a minimum
version without reimplementing lapin's handshake. rustls's default version set
is TLS 1.2 **and** 1.3, so a broker that offers only 1.2 is accepted today.

Set the floor on RabbitMQ, where it is enforceable and where it also covers
every other client of the same broker:

```ini
# rabbitmq.conf
ssl_options.versions.1 = tlsv1.3
```

Verify it from outside the cluster:

```bash
# must succeed
openssl s_client -connect rabbitmq:5671 -tls1_3 </dev/null
# must fail
openssl s_client -connect rabbitmq:5671 -tls1_2 </dev/null
```

### A supplied CA bundle is ADDED to the platform roots, not substituted

`AXIAM__AMQP__TLS__CA_CERT_PATH` does **not** narrow trust to your CA. The
bundle is added on top of the platform verifier's existing root set
(`tcp-stream`'s rustls backend calls `add_parsable_certificates`), so after
setting it, a certificate for the broker's hostname issued by any publicly
trusted CA is still accepted. The trust set got wider, not narrower.

If you need it genuinely restricted to your CA, do it in the container's
platform trust store and leave the variable unset — or, better, authenticate
the broker with **mutual TLS** (`AXIAM__AMQP__TLS__CLIENT_CERT_PATH` +
`..._KEY_PATH`), which is a stronger statement than root pinning and is what
the `rabbitmq-broker-tls` Secret above is already shaped for.

### Every stack is TLS, including dev, e2e and bench

There is no plaintext AMQP anywhere, and no configuration that produces any.
`amqps://` or the server refuses to start — in a debug build exactly as in a
release one.

This replaced an earlier posture worth recording, because the earlier one is
the shape this failure usually takes. A release binary used to refuse plaintext
*unless* `AXIAM__AMQP__ALLOW_PLAINTEXT=true` was set, and the flag logged a
prominent warning naming what was readable on the wire. Four stacks set it —
dev compose, the e2e stack, the benchmark target and CI — and each had a
genuinely reasonable local argument: throwaway data on a compose network, an
ephemeral broker carrying synthetic fixtures for one job, a hop the benchmark
harness is trying to measure rather than encrypt. None of those arguments was
wrong. The aggregate was: "AMQP is TLS-only" described the production compose
file and the k8s manifests, and nothing else this repository actually runs.

What it costs now, in full:

- `just dev-up` calls `scripts/gen-broker-tls.sh` before starting the broker
  (idempotent — existing material is left alone, so it will not rotate a cert
  out from under a running container);
- CI's test and coverage jobs start RabbitMQ with `docker run` rather than as a
  `services:` container, because a service container starts before any step
  could mint the certificate it needs to mount;
- the E2E and examples-smoke jobs mint a throwaway CA per run;
- `just bench-up` mints stable bench material — and **AMQP-carrying benchmark
  figures are not directly comparable across this change**, since that hop was
  plaintext through run 5. Re-baseline rather than extending a trend line.

The generated broker certificate carries `rabbitmq`, `localhost` and
`127.0.0.1` in its SAN, so one set of material serves both the compose network
and a `cargo test -- --ignored` run on the host.

`scripts/check-amqp-transport.py` enforces this at PR time, and CI runs it in
the Security Scan job. It now requires `amqps://` outright, and also reports a
leftover `AXIAM__AMQP__ALLOW_PLAINTEXT` anywhere it survives — a stale copy of
an old snippet is how the plaintext URL that went with it comes back. Without
this check the sole symptom of a missed stack is a container that refuses to
boot, which is easy to misread as an unrelated infrastructure fault.

### Two things to decide before you put AXIAM in front of RabbitMQ

**Broker-wide `fail_if_no_peer_cert` needs a certificate AXIAM cannot issue
yet.** Requiring a client certificate from every AMQPS connection is the right
posture, and it includes AXIAM's own lapin client. That client connects during
startup — before the REST API is listening, before an organization CA exists,
and certainly before anything has called `POST /api/v1/certificates`. There is
no ordering that lets AXIAM issue the certificate it needs in order to start.

So issue it **offline, from the same root**: generate AXIAM's broker client
certificate with the same CA (or an offline intermediate under it) that signs
the rest of the fleet, mount it, and point
`AXIAM__AMQP__TLS__CLIENT_CERT_PATH` / `..._CLIENT_KEY_PATH` at it. Once AXIAM
is up it can issue the *devices'* certificates from its own CA and they chain to
the same root the broker already trusts, which is the arrangement that makes one
trust store serve both. `scripts/gen-broker-tls.sh` is the shape of this for a
development stack; production wants your own CA and your own key custody. The
alternative — bootstrapping AXIAM against a broker that does not require peer
certificates and tightening it afterwards — leaves a window in which it does not
require them, and an operator who forgets step two.

**AXIAM's access tokens are not consumable by
`rabbitmq_auth_backend_oauth2`.** That plugin reads a JWT's `scope` claim and
turns entries such as `rabbitmq.configure:%2f/*` into broker permissions. AXIAM
does mint `scope`, but it is an OAuth2 authorization-server claim describing
scopes a client *requested and was granted* against AXIAM's own resources — an
application-defined vocabulary, and one the plugin's grammar has no bearing on.
On the path that matters here it is not merely different, it is absent: the
device login (`POST /api/v1/auth/device`) has no way to request a scope and a
service account registers none, so the claim is omitted entirely. A token that
carries no `scope` grants no RabbitMQ permission, and the plugin's answer is to
refuse the connection.

The arrangement that does work, and the one the reference integration uses, is
**certificate login plus an HTTP auth backend**: `rabbitmq_auth_mechanism_ssl`
takes the identity from the client certificate the device already presents,
and `rabbitmq_auth_backend_http` asks a small endpoint of yours — which is free
to call AXIAM's authorization API — for the vhost, resource and topic
decisions. That keeps one identity per device, issued by AXIAM, and puts the
permission model where RabbitMQ can express it. Mapping AXIAM roles onto the
plugin's `scope` grammar in a token is a *possible* third option, and it means
minting a second, RabbitMQ-shaped token; it is not what these variables
configure and it is not covered here.

### Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `AXIAM__AMQP__ENABLED` | `true` | `false` selects the [minimal profile (no broker)](#minimal-profile-no-broker): no connection, no topology, no URL or signing key needed, single instance only. |
| `AXIAM__AMQP__URL` | `amqps://localhost:5671` | **Must** be `amqps://`. Every other scheme is refused before a socket is opened. |
| `AXIAM__AMQP__TLS__CA_CERT_PATH` | *(unset)* | PEM bundle for the broker's issuing CA, **added to** the platform roots (not substituted — see above). Unset = platform roots only. |
| `AXIAM__AMQP__TLS__CLIENT_CERT_PATH` | *(unset)* | PEM client certificate, for mutual TLS. Requires the key. |
| `AXIAM__AMQP__TLS__CLIENT_KEY_PATH` | *(unset)* | PEM client key. Requires the certificate. |
| `AXIAM__AMQP__CONNECT_TIMEOUT_MS` | `30000` | Budget for one connection attempt. lapin has none of its own, so without this a broker whose port is published but whose TLS listener never answers leaves the connect pending forever — no error, no retry, no log line. Raise it for a broker behind a slow link; do not disable it. |

## Minimal profile (no broker)

`AXIAM__AMQP__ENABLED=false` runs AXIAM with **SurrealDB only**: no RabbitMQ, no
`AXIAM__AMQP__URL`, no AMQP signing key. It is meant for a single node, an edge
site or a small deployment where a broker is more infrastructure than the
workload justifies. The default is `true`, and with it nothing on this page
applies.

### It is single-instance, by definition

**Run exactly one instance.** Without a broker nothing tells a second replica
about the first one's mutations — a revoked role, a changed permission — so a
second instance would serve stale authorization decisions and no setting makes
it correct. AXIAM does not trust a replica count to say so (it is the
orchestrator's knowledge, not the process's): the minimal profile holds a
**singleton lease** in SurrealDB and refuses to run beside another instance.

* the lease is the row `minimal_profile_lease:instance` (schema v83), claimed
  with a conditional write at start-up, valid for **30 s** and renewed every
  **10 s**;
* a boot that finds another instance's live lease **waits up to 45 s** for it
  to expire — a rolling update's old pod stops renewing when it stops — and then
  refuses to start;
* an orderly stop releases the lease, so a successor does not wait at all;
* an instance whose renewal finds the lease **taken by another instance logs
  once at `ERROR` and exits non-zero**, rather than keep running beside it. It
  exits through the orderly stop a `SIGTERM` takes — no new connections,
  in-flight requests finished, queued audit rows written — within **15 s**,
  after which a backstop ends the process regardless.

On Kubernetes that means `replicas: 1` and, for the rolling-update case,
`strategy: Recreate` (or `maxSurge: 0`); the 45 s wait covers a surge pod that
starts before the old one is gone, and a crash-looping pod simply tries again.
The clocks of two instances sharing a datastore must agree to well within the
30 s TTL, which any NTP-disciplined host does.

### Run it

```bash
just minimal-up      # SurrealDB + axiam-server, no broker
curl -s http://localhost:8090/health
just minimal-down    # stop; the data volumes are kept
just minimal-clean   # stop and DELETE the datastore and the audit dead-letter file
```

[`docker/docker-compose.minimal.yml`](../../docker/docker-compose.minimal.yml)
runs **one** `axiam-server` (there is no `deploy.replicas` in it, and the
fixed `container_name` makes Compose refuse `--scale`) and one SurrealDB — no
RabbitMQ, no broker TLS material, no Vault. It pulls the released server image
like `docker-compose.prod.yml` does, so `AXIAM_IMAGE_TAG` must name a release
that contains `AXIAM__AMQP__ENABLED` (an older image ignores the variable and
then refuses to boot for want of a broker); `just minimal-up` defaults it to the
workspace version. To build from the working tree instead, uncomment the
`build:` block on `axiam-server`.

On first run `just minimal-up` mints what the server needs into
`docker/.secrets/` (gitignored): the SurrealDB credentials, an Ed25519 JWT
keypair, `AXIAM__AUTH__PEPPER` (mandatory in a release build) and the
encryption keys the production stack seeds into Vault — email (without it no
mail is sent), GDPR pseudonym pepper (without it the erasure sweep is skipped),
MFA, federation, PKI and OPAQUE; only the AMQP signing key is left out. They
come from the environment (`AXIAM__AUTH__SECRET_PROVIDER=env`); the Vault path
of [`vault.md`](vault.md) works unchanged if you want it. The peppers and keys
are what stored hashes and sealed secrets were made with — back them up with the
datastore. The stack has its own Compose project name (`axiam-minimal`), so
its volumes can never be the dev or prod stack's.

Both ports are published on the loopback interface only: put a TLS-terminating
proxy in front of the REST port. The compose file also gives the server a
**40 s stop grace period** and a named volume for the audit dead-letter file
(below).

**On Kubernetes** the same profile is: `AXIAM__AMQP__ENABLED=false`, no
`AXIAM__AMQP__*` URL, TLS or signing-key settings, no RabbitMQ, **`replicas: 1`**
with `strategy: Recreate`, a `terminationGracePeriodSeconds` of at least 40 (the
default of 30 is too short; see
[the grace period](#stopping-and-the-grace-period)), and a small volume for
`AXIAM__GDPR_AUDIT_DLQ_FILE` — the server's
manifest runs with `readOnlyRootFilesystem: true`, so without a mounted path the
file sink cannot be written. `k8s/server/deployment.yml` mounts one (an
`emptyDir`; see [the audit dead-letter file](#the-audit-dead-letter-file) for
what that survives).

### What it does not provide

`GET /health` says so, in `unavailable` (see below):

| Not available | What happens instead |
|---|---|
| **Reactors** (`reactors`) | Enabling a registration through `POST`/`PUT /api/v1/reactors` answers **`409`** naming the profile, and the gRPC `ReactorAdminService` answers `FAILED_PRECONDITION`. A registration created with `enabled: false` is accepted, and so are disabling and deleting one. |
| **Asynchronous authorization over AMQP** (`amqp_authz`) | The authorization request consumer is not started. REST and gRPC authorization checks are unaffected. |
| **External audit ingestion over AMQP** (`amqp_audit_ingestion`) | The consumer that ingests audit events *published by other services* is not started. AXIAM's **own** audit events never touched AMQP — the audit middleware writes SurrealDB directly — and are unchanged. |
| **Cross-replica decision-cache invalidation** (`decision_cache_broadcast`) | There is no second replica to tell. The decision cache itself (`AXIAM__AUTHZ__DECISION_CACHE_ENABLED`) works, process-locally and exactly. |

**A minimal-profile server reads no AMQP queue.** It does not consume
`axiam.authz.request` or `axiam.audit.events`, whatever a broker holds, so a
service that publishes to a broker left running next to it is confirmed by that
broker while nothing reads the message. **A broker confirm never means AXIAM
recorded an event** (nor decided an authorization): it says only that the broker
accepted the message. A client that needs a decision uses REST or gRPC, which
are unchanged; a service that needs its events in AXIAM's audit trail needs the
full profile. The AMQP SDKs' READMEs say the same.

Everything that rode a broker queue still works, on **in-process queues**:

* **webhooks, SSF push, outbound SCIM and CIBA ping** run on one in-process
  dispatcher with the *same* deliverers, the *same* retry policy
  (`AXIAM__WEBHOOK__*`, `AXIAM__SSF_PUSH__*`, `AXIAM__SCIM_PUSH__*`,
  `AXIAM__CIBA_PING__*`: attempts, base and ceiling of the exponential
  backoff) and the *same* audit rows (`<kind>.delivery_attempt`,
  `.delivery_succeeded`, `.delivery_failed`) as the AMQP path, plus one the
  broker path has no use for, `<kind>.delivery_abandoned` (below);
* **transactional mail** (verification, password reset, notification rules, GDPR
  export notices, CIBA approval) is sent by an in-process worker with the same
  retry count and the same PII-minimal `email.delivery_failed` audit row, and
  needs `AXIAM__AUTH__EMAIL_ENCRYPTION_KEY` exactly as before.

### What is lost on restart

**Queued outbound messages and queued mail do not survive a restart.** There is
no durable queue: a delivery that is waiting for its turn or sleeping for a
retry when the process stops is gone, and there is **no dead-letter queue** —
for a delivery that exhausts its attempts the `<kind>.delivery_failed` audit row
is the whole record, so alert on it. A producer whose queue is full (1 024
messages per kind, 1 024 for mail) gets an enqueue error, which every producer
already logs and swallows; a retry that finds no free retry slot (1 024 may be
sleeping at once) is dead-lettered with the reason `in-process retry capacity
exhausted`. If a lost webhook is not acceptable, run the full profile.

What the dispatcher does record is that it lost a delivery. At an orderly stop,
and when a queue refuses an enqueue, it writes one terminal
**`<kind>.delivery_abandoned`** audit row (outcome `Failure`, the system actor,
the target as the resource) per lost delivery, with a fixed `reason`:
`in-process dispatcher stopped before the delivery completed`,
`in-process queue full; the delivery was not accepted` or
`in-process dispatcher not running; the delivery was not accepted`, and the
delivery id and the number of attempts already made. It is a different action
from `delivery_failed` on purpose: a restart is not a downstream outage, so the
`scim_delivery_failed` notification event (which matches
`scim_push.delivery_failed` only) does not mail anyone for it. Alert on
`delivery_abandoned` separately if a lost delivery matters to you; it is
written only when the process gets to stop in order (see below).

In audit terms, a restart loses the following, and nothing else:

* **A webhook, SSF, outbound SCIM or CIBA-ping delivery that was queued or
  waiting for a retry** at an *orderly* stop leaves a terminal
  `<kind>.delivery_abandoned` row (above). After a `SIGKILL`, an out-of-memory
  kill or a stop that overran its backstop it leaves at most a
  `<kind>.delivery_attempt` row and no terminal one. A delivery refused because
  its queue was full leaves a `delivery_abandoned` row too (and the producer's log
  line). Outbound SCIM is repaired by the next reconciliation; webhooks, SSF
  events and CIBA pings are not redelivered. Queued mail is not covered by the
  row: it has no per-message audit trail of this kind.
* **A Security Event Token** that the SSF outbox had released to the push queue
  is lost with it. Receivers must already treat SSF signals as hints (the
  threat model's T-405); in the full profile a queued push is at-least-once, in
  the minimal one it is not.
* **A GDPR export notice (`ExportReady` mail)** that was still queued cannot be
  re-sent: the download token exists only hashed in the datastore and its raw
  value travels only in that mail. The export is marked ready but the subject
  cannot download it, and no row says the notice was not sent. **The subject
  requests a new export.**

### Stopping, and the grace period

An orderly stop — `SIGTERM`, or a lost lease — stops accepting connections,
finishes the requests in flight, finishes the cleanup tick it is in (so a GDPR
erasure and its audit row stay together) and then **writes the audit rows the
audit middleware still holds, waiting up to 5 s for it**, before the process
exits. Before that drain, in the minimal profile, each in-process outbound
queue is closed and one `<kind>.delivery_abandoned` row is written for every
delivery still queued or waiting for a retry. A `SIGKILL` or an out-of-memory
kill does none of that and loses what is queued.

**Give the container a termination grace period of at least 40 s.** The stop
has four bounded steps. The REST listener waits up to **20 s** for requests in
flight (`shutdown_timeout`, set explicitly in `boot.rs`; actix's own default is
30 s). The gRPC server then gets up to **5 s** to finish its calls, the
in-process outbound queues up to **2 s** (`OUTBOUND_DRAIN_DEADLINE`) to account
for what they hold, and the audit queue up to **5 s** (`AUDIT_DRAIN_DEADLINE`)
to be written. That is 32 s, and 40 s leaves a margin. A shorter grace period lets the orchestrator kill the process
during the drain, which loses exactly the audit rows the orderly stop exists to
keep. Compose's default is 10 s and Kubernetes' is 30 s, so both are set:
`stop_grace_period: 40s` in `docker-compose.prod.yml` and
`docker-compose.minimal.yml`, and `terminationGracePeriodSeconds: 40` in
`k8s/server/deployment.yml`. If you change the shutdown timeout, move the grace
period with it. An instance that loses its lease, or whose consumer or gRPC
server dies, stops accepting at once, finishes in-flight requests and exits
non-zero. A backstop ends the process regardless if the stop overruns: 15 s
after it began for a lost lease (which must not run beside its successor for
longer), 35 s — the four steps and a margin, inside the grace period — for a
dead consumer or gRPC server.

### Audit durability

AXIAM's own audit rows are written straight to SurrealDB in both profiles; the
broker never carried them. What the profile changes for audit — the terminal
rows of deliveries lost on restart, external audit ingestion — is reviewed path
by path in
[`claude_dev/audit-durability-review-minimal-profile-2026-10-05.md`](../../claude_dev/audit-durability-review-minimal-profile-2026-10-05.md).

#### The audit dead-letter file

An audit row the datastore refuses is never lost to a log line alone (T19.27,
T-108). These go to a dead-letter file when `AXIAM__GDPR_AUDIT_DLQ_FILE` names
one:

* the two legally significant GDPR records written by the cleanup sweep and the
  tenant API, `gdpr.user_pseudonymized` (the erasure) and `tenants.deleted`;
* the two GDPR *request* records, `gdpr.data_export_requested` and
  `gdpr.erasure_requested` (the request itself has succeeded by then; only the
  record of it was refused);
* request-audit rows that were dropped or failed to append (below).

The records written by the sweep and by the GDPR handlers also go to a second
sink, a structured log event on the target `axiam.audit.dlq`.

1. **An append-only file**, named by `AXIAM__GDPR_AUDIT_DLQ_FILE`. One JSON line
   per record, the fields of an audit entry (`tenant_id`, `actor_id`,
   `actor_type`, `action`, `resource_id`, `outcome`, `ip_address`, `metadata`);
   the server opens it for append and never rewrites or truncates it. It is
   configured in every shipped deployment, always at
   `/var/lib/axiam/audit-dlq/gdpr-audit-dlq.jsonl`:

   | Deployment | Volume | Survives |
   |---|---|---|
   | `docker-compose.minimal.yml` (project `axiam-minimal`) | named volume `gdpr-audit-dlq` | container removal and recreation; lost only by `just minimal-clean` |
   | `docker-compose.prod.yml` (project `docker`) | named volume `gdpr-audit-dlq` | container removal and recreation; lost by `just prod-clean` (`down -v`) |
   | `k8s/` | `emptyDir` named `audit-dlq`, `sizeLimit: 256Mi` | a container restart (OOMKill, failed probe); **not** the pod's deletion (rollout, drain, eviction, node loss) |

   **The file's budget.** `AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES` bounds it, in bytes:
   192 MiB (`201326592`) when unset, at least 1 MiB; a value that is not a whole
   number of bytes, or is below the minimum, fails the boot. Request-audit rows
   fill at most nine tenths of the budget; past that each is refused, counted in
   `not_recoverable`, and `/health/jobs` reports `dead_letter_full` (and
   `degraded`) until the file is replayed and moved with the server stopped. The
   last tenth is a reserve only the GDPR records write into, so a flood of
   request rows cannot crowd out an erasure record; a GDPR record that would
   cross the whole budget is refused too and kept on `axiam.audit.dlq` only. The
   size is checked before each write, so the file can pass the budget by at most
   one batch of rows. Each line's client-sized fields are cut with a
   `...[truncated]` marker: `action` (the request's method and path) to 512
   bytes and `ip_address` (the forwarded client address) to 64, which bounds a
   request row's line to about a kilobyte; the audit row in the datastore is cut
   the same way. Every shipped deployment states the budget: the ConfigMap key in
   `k8s/server/configmap.yml`, `AXIAM_GDPR_AUDIT_DLQ_MAX_BYTES` in both Compose
   files.

   Back the Compose volumes up with the datastore. A volume Compose creates is
   root-owned, so each file has a one-shot init service (`volume-init`,
   `gdpr-audit-dlq-init`) that hands it to the server's user (65532).

   **Why the Kubernetes volume is an `emptyDir`.** `axiam-server` is a
   Deployment of 2–10 replicas under an HPA, and the file is per replica. One
   PersistentVolumeClaim would be a `ReadWriteOnce` volume shared by every
   replica (a pod on another node cannot attach it), and one claim per replica
   means a StatefulSet, a different workload with a different rollout. So the
   manifests choose a spill volume that survives what is most likely, a
   container restart, and **replay the file before you roll the Deployment**
   while it holds rows. If the file must outlive the pod, replace the volume in
   `k8s/server/deployment.yml` with a per-replica one (a StatefulSet's
   `volumeClaimTemplates`, or a CSI ephemeral volume) and keep the path. The
   `sizeLimit` is a backstop that must never be reached: the kubelet enforces
   it by **evicting the pod, and eviction deletes the `emptyDir` and the file
   with it** — every unreplayed row, at the moment the file is fullest, and in a
   datastore outage on every replica at about the same time. The budget above is
   what keeps the file from reaching it, so keep `AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES`
   below the `sizeLimit` and change the two together. On Compose the named
   volume has no limit and shares the Docker root with the datastore's volume;
   there the budget is what keeps a flood off the datastore's disk. The path is
   the ConfigMap key `AXIAM__GDPR_AUDIT_DLQ_FILE` in
   `k8s/server/configmap.yml`, so an overlay that replaces the container's
   `env` (the Raspberry Pi overlay does) keeps it.
2. **A structured log event** on the target `axiam.audit.dlq`, for the GDPR
   records. It is the only sink for them when the file variable is unset, so
   collect the container log as well.

**With the variable unset** the server logs one `WARN` at start (naming the
variable), a refused request-audit row is counted and logged only, and a refused
GDPR record is logged on `axiam.audit.dlq` only. Neither is recoverable from the
server afterwards.

The server does not read the file back. An operator **replays it into the trail
by hand**, once the datastore is healthy. There is no replay command; the file
is the recipe's input and each line maps one-to-one onto a `CREATE audit_log
SET …` statement. A JSON `null` has to become `NONE` (SurrealDB refuses `NULL`
for an optional field). With `jq` and the SurrealDB shell (the namespace and
database are `AXIAM__DB__NAMESPACE` / `AXIAM__DB__DATABASE`, both `axiam` in the
shipped files). Minimal profile; for `docker-compose.prod.yml` use the volume
`docker_gdpr-audit-dlq`, the container `axiam-surrealdb` and the credentials in
`docker/.secrets/stack-credentials.env`:

```bash
source docker/.secrets/minimal-credentials.env   # the datastore credentials
# a distroless image has no shell, so read the volume rather than the container:
docker run --rm -v axiam-minimal_gdpr-audit-dlq:/d busybox cat /d/gdpr-audit-dlq.jsonl > gdpr-audit-dlq.jsonl

jq -r '"CREATE type::record(\"audit_log\", <string>rand::uuid::v7()) SET tenant_id = \(.tenant_id|@json), actor_id = \(.actor_id|@json), actor_type = \(.actor_type|@json), action = \(.action|@json), resource_id = \(.resource_id // null | if . == null then "NONE" else @json end), outcome = \(.outcome|@json), ip_address = \(.ip_address // null | if . == null then "NONE" else @json end), metadata = \(.metadata // {} | tojson);"' \
    gdpr-audit-dlq.jsonl \
  | docker exec -i axiam-minimal-surrealdb /surreal sql --endpoint ws://127.0.0.1:8000 \
      --user "$AXIAM__DB__USERNAME" --pass "$AXIAM__DB__PASSWORD" --ns axiam --db axiam --hide-welcome
```

On Kubernetes the pipeline is the same with two substitutions. Read the file from
the pod with an ephemeral container that shares the server's process namespace
(the image has no shell and no `tar`, so `kubectl cp` does not work):
`kubectl -n axiam debug -it <axiam-server-pod> --image=busybox --target=axiam-server -- cat /proc/1/root/var/lib/axiam/audit-dlq/gdpr-audit-dlq.jsonl > gdpr-audit-dlq.jsonl`
(the namespace enforces Pod Security `restricted`, so add `--profile=restricted` where
your `kubectl` has it). And pipe the statements into
`kubectl -n axiam exec -i surrealdb-0 -- /surreal sql …` with the datastore's
credentials. Do this for **each replica's** file. This path was not exercised against a cluster;
the statements are the same ones the test below checks.

The format and the statement are checked by `gdpr_audit_dlq_test.rs`
(`the_replay_recipe_in_the_docs_restores_dead_lettered_rows`): it takes the
`jq` filter out of this page, runs it over lines written by the dead-letter
writer, applies the statements to a migrated datastore and reads the rows back
and, because it reads the rows back through the audit repository, that each
replayed row is one AXIAM can list. The statement gives the row a UUID record
id (`rand::uuid::v7()`); an earlier form of this recipe let SurrealDB generate
the id, and AXIAM's audit list fails for the whole tenant while such a row is in
it (`invalid UUID`). Rows replayed with that form have to be removed with the
datastore's root account, which the table's append-only permission does not bind,
and replayed again with this one. The replayed row's `timestamp` is the moment of
replay — when the original write failed is in the `axiam.audit.dlq` log event, so keep the log
with the file — and, like every audit row, it can neither be updated nor
deleted afterwards, so **replay each line once**. Note how many lines you
replayed (`wc -l gdpr-audit-dlq.jsonl`) and start the next replay after them
(`tail -n +N`). Do not rename or delete the file while the server runs: the
request-audit writer keeps its handle open and would keep appending to the
renamed file. To start a fresh one, stop the server, move the file, start it.
An empty or missing file means no record has been dead-lettered. The same file
also receives request-audit rows that were dropped or failed to append, below.

#### Lost request-audit rows (`/health/jobs`)

The audit middleware records every request on a background worker, off the
request path, through a queue of 4 096 rows. A row is lost in two ways: the queue
is full when the request ends (**dropped**), or the datastore refuses the append
(**failed**). The response has already gone out either way (T-108).

`GET /health/jobs` (same exposure as before: server root, internal network only)
reports both in a `request_audit` object beside `jobs`:

| Field | Meaning |
|---|---|
| `dropped`, `failed` | Rows lost since this process started; they only go up. |
| `dead_lettered` | Lost rows written to the dead-letter file. |
| `not_recoverable` | Lost rows kept nowhere: no file is configured, or it could not take them. |
| `dead_letter_configured` | Whether `AXIAM__GDPR_AUDIT_DLQ_FILE` names a file. |
| `dead_letter_full` | Whether the file has reached the request rows' share of its budget (`AXIAM__GDPR_AUDIT_DLQ_MAX_BYTES`); further lost rows are refused by it and counted in `not_recoverable`. |
| `last_loss_at`, `recent_loss` | When the last row was lost; whether that was in the last 15 minutes. |

`status` is `degraded` while `recent_loss` is true and returns to `ok` by itself
once rows are being recorded again, and is `degraded` while `dead_letter_full`
is true, which only a replay and a restart clear; the endpoint stays HTTP 200, as for a
stalled job. Alert on `status == "degraded"`, or on the rate of `dropped +
failed`. The counters are per process: a restart resets them and each replica
reports its own. The server also logs one `ERROR` line on the target
`axiam.audit.loss` for the first lost row and then at most once a minute, naming
the totals.

**The dead-letter file takes these rows too.** When `AXIAM__GDPR_AUDIT_DLQ_FILE`
is set, each dropped or failed row is appended to the same file as the GDPR
records, in the same one-JSON-line form, and replayed with the same statement as
above. The write is queued to a writer task (up to 1 024 rows), so the request
path does no file I/O; a row the writer cannot keep — its queue is full, the
file is at its budget, or the file cannot be written — is counted in
`not_recoverable`. The lines carry no reason or time — the `axiam.audit.loss` log
lines give the former, and the replayed row's `timestamp` is the replay's. With
the variable unset the server logs one warning at start (it covers these rows
and the GDPR records alike) and lost rows are counted and logged only. Both
Compose files and the Kubernetes manifests set the variable; set it, on a
volume the server's user can write, in any other deployment.

Still lost: a row that was in the queue (or the writer's queue) when the process
was killed rather than stopped — an orderly stop drains both — and a row refused
when the file is not configured, not writable or full.

#### External audit producers

Before switching a deployment to the minimal profile, **stop or re-point every
service that publishes to `axiam.audit.events`.** Nothing consumes that queue:
there is no REST or gRPC route for an external audit event, so there is no other
ingestion path. A broker left running confirms the publish anyway, so the
producer is not told; and returning to the full profile later dead-letters
everything older than `AXIAM__AMQP__REPLAY_SKEW_SECS` (300 s by default) to
`axiam.audit.events.dlq`. AXIAM's **own** audit events are unaffected.

### Boot refusals

Each is an error that names `AXIAM__AMQP__ENABLED=false` and the fix; the
process does not start.

| Refused | Why | Fix |
|---|---|---|
| `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED=true` | the broadcast has no transport | unset it |
| **any enabled reactor registration** in the datastore, in any tenant | a `fail_closed` reactor with no transport would deny `login.post_auth`, `user.pre_create`, `user.pre_update` and `grant.pre_assign` in every tenant that registered one | `PUT /api/v1/reactors/{id}` with `enabled: false` (or delete it), or run the full profile |
| **a second live instance** | see above | stop the other instance |

### `/health`

`GET /health` always answers `200` and now states the profile (additive — a
client that reads only `status` is unaffected):

```json
{ "status": "ok", "profile": "minimal",
  "unavailable": ["reactors", "amqp_authz", "amqp_audit_ingestion", "decision_cache_broadcast"] }
```

`profile` is `"full"` or `"minimal"`; `unavailable` is present only in
`minimal`.

### When to choose it, and how to move between profiles

| Choose the **minimal** profile when | Choose the **full** profile when |
|---|---|
| one instance is enough, now and for the foreseeable future | you need more than one instance (availability, rolling updates without a wait, load) |
| a webhook, SSF event or mail queued at the moment of a restart may be lost | a queued delivery must survive a restart — the broker holds it and the next run writes its audit row |
| you use none of Reactors, asynchronous authorization over AMQP, external audit ingestion over AMQP | you use any of them |
| a broker is more infrastructure than the workload justifies (a single node, an edge site, an evaluation) | you already run RabbitMQ, or need the cross-replica decision-cache invalidation |

**Minimal → full.** In this order:

1. Stop the minimal instance (an orderly stop releases the lease, and a
   delivery still queued in process is lost with it — stop the traffic that
   produces deliveries first and give the queue a minute to drain).
2. Provision RabbitMQ (TLS-only, see the sections above) and an AMQP signing key.
3. Start **one** instance with `AXIAM__AMQP__ENABLED=true` (or the variable
   removed), `AXIAM__AMQP__URL`, `AXIAM__AMQP__TLS__CA_CERT_PATH` and
   `AXIAM__AMQP__SIGNING_KEY`. `GET /health` now says `"profile": "full"` and has
   no `unavailable` list.
4. Only then add replicas, enable Reactors and point external audit producers
   back at `axiam.audit.events`. The `minimal_profile_lease` row stays in the
   datastore, unread by the full profile.

**Full → minimal.** The boot refusals above are the checklist, plus what no
refusal can see:

1. Run exactly one instance before the switch.
2. Disable (`PUT /api/v1/reactors/{id}` with `enabled: false`) or delete every
   Reactor registration in every tenant.
3. Unset `AXIAM__AUTHZ__DECISION_CACHE_BROADCAST_ENABLED`.
4. Stop or re-point every service that publishes to `axiam.audit.events`, and
   move any caller of asynchronous authorization over AMQP to REST or gRPC.
5. While the full profile is still running, let the broker's AXIAM queues
   (`axiam.webhook` and the queues of the other outbound kinds) drain: the minimal profile does not read
   them, so what is left there is neither delivered nor audited.
6. Set `AXIAM__AMQP__ENABLED=false`; the broker URL, TLS and signing-key
   settings are no longer needed. Check `GET /health` for `"profile": "minimal"`.

### Resting footprint

The whole-stack **resting** footprint, measured on 2026-10-05 — idle, **not under
load**, on a freshly migrated empty datastore (no tenant, no user, no traffic):

| | `axiam-server` | SurrealDB | RabbitMQ | **Whole stack** |
|---|---|---|---|---|
| **Minimal** (no broker) | 120.7 MiB | 86.6 MiB | — | **207.3 MiB** |
| Full (with RabbitMQ) | 130.3 MiB | 86.0 MiB | 114.6 MiB | **330.9 MiB** |

Median resident set (`VmRSS`) over the sampling window; the anonymous part
(heap and stacks, no mapped file pages) is 113.5 MiB for the minimal stack and
185.0 MiB for the full one. Dropping the broker saves about 124 MiB (37 %), of
which 10 MiB is the server's own AMQP machinery and the rest RabbitMQ. Repeat
runs of the minimal stack agreed to within 2 MiB (205.5–207.3 MiB).

How it was measured, so the number can be reproduced and not over-read:

* **Method.** `benchmarks/resting-footprint/measure.sh`: start SurrealDB (and
  RabbitMQ for the full stack) as containers, start the server, wait for
  `GET /ready` to answer `200`, settle for 60 s, then sample the resident set of
  every component every 5 s for 120 s (the run took 15–20 samples, because
  reading a container's processes is not instantaneous). Raw samples, summaries,
  server logs and the environment (versions, digests, host) are in
  `benchmarks/resting-footprint/2026-10-05/`.
* **Envelope.** SurrealDB 2 CPU / 1 GiB and RabbitMQ 1 CPU / 512 MiB, the caps
  the benchmark harness uses; **the server ran as the native release binary**
  (`--features jemalloc`, as the shipped image is built, built from commit `21f1521`),
  uncapped, next to the containers — not as a container. A measurement of the
  server *image* has not been taken.
* **Versions.** SurrealDB 3.2.5 (`surrealdb/surrealdb:v3`, digest
  `sha256:eb6dddd6…`), RabbitMQ `4-management-alpine` (digest `sha256:3ef7f7e8…`),
  on a 4-vCPU Linux 6.18 host.
* **What the RSS figure includes.** File-backed pages count (the server's own
  binary, ~32 MiB of its 121 MiB; SurrealDB's mapped datastore, ~62 MiB of its
  87 MiB), which a container's cgroup accounting largely does not — which is why
  these figures are not comparable cell for cell with the *under load*,
  container-averaged figures in the benchmark analysis (§5).
* **At rest means at rest.** Memory under load grows with the working set and the
  load; this is the floor, not the ceiling. SurrealDB's figure depends on the
  size of the datastore.

### Tests, by profile

The full REST and gRPC suites run without a broker (they build their state with
`AppState::for_test`), and `crates/axiam-server/tests/minimal_profile_boot.rs`
boots the real composition root with the flag off — no broker, no datastore
server — signs in, and watches a webhook and an SSF Security Event Token arrive
through the in-process dispatcher. The tests that need a live RabbitMQ (they are `#[ignore]`d and run against
`just dev-up`) are specific to the full profile and are skipped for the minimal
one: `amqp_recovery_test` and `reactor_containerized_test` in `axiam-amqp`, and
`webhook_consumer_test` in `axiam-api-rest`. Everything else — including the
reactor administration tests, which run both ways: `409` in the minimal profile,
`503` for a build that composes no transport — needs no broker.

## Outbound SSRF guard — same-network IdPs (`AXIAM__PKI__SSRF_ALLOWED_HOSTS`)

Every outbound fetch to an admin- or IdP-supplied URL is refused if the host
resolves to a non-globally-routable address. **A deployment whose IdP, webhook
consumer or MDS mirror lives on an internal network must name those hosts
explicitly**, or the fetch fails with `SsrfError::Blocked` at runtime:

```
AXIAM__PKI__SSRF_ALLOWED_HOSTS=keycloak.internal,idp.corp.example
```

Host names or literal IPs, comma-separated, matched **exactly** — no wildcards,
no suffix matching, no CIDRs. Unset (the default) means no exceptions at all.
The exception applies to the first hop only; redirect targets are always
validated strictly, and cloud metadata endpoints stay unreachable even for an
allowlisted host. Every use is logged.

The full reasoning, and the five properties that keep this from being a bypass,
are in [`../security-profiles.md`](../security-profiles.md#outbound-ssrf-guard--the-operator-override-sec-107).

## The issuer, and per-tenant path issuers (optional, T21.6)

`AXIAM__AUTH__OAUTH2_ISSUER_URL` — the deployment's issuer identifier.
`AXIAM__AUTH__TENANT_ISSUER_PATHS` — default `false`.

### The root issuer

`AXIAM__AUTH__OAUTH2_ISSUER_URL` is the `issuer` of the discovery document, the
`iss` of every token AXIAM mints, and the base every endpoint URL is built from.
It must be a **bare root URL** — `https://id.example.com`, not
`https://id.example.com/auth` — and the server refuses to start otherwise. It
must be `https` except on `localhost`, and it may carry neither a query nor a
fragment, which is what RFC 8414 §2 requires of an issuer identifier.

If it is unset the server falls back to `AXIAM__AUTH__JWT_ISSUER`, which is a
bare identifier rather than a URL. That is enough to sign tokens and not enough
to publish a conformant discovery document, so set it on any deployment a third
party talks to.

### Two ways to name a tenant

AXIAM is multi-tenant and one issuer serves every tenant, so something in the
request has to say which tenant it is for. There are two forms, and a deployment
chooses one at boot.

**`?tenant_id=` — the default.** Every endpoint that authenticates a client
takes a `tenant_id` query parameter, and the discovery document publishes the
endpoint URLs with it already attached:

```console
$ curl -s https://id.example.com/.well-known/openid-configuration\
?tenant_id=6f9619ff-8b86-d011-b42d-00c04fc964ff | jq -r .issuer,.token_endpoint
https://id.example.com
https://id.example.com/oauth2/token?tenant_id=6f9619ff-8b86-d011-b42d-00c04fc964ff
```

Note what the two lines say: the endpoints name the tenant, and the **issuer
does not**. It cannot — RFC 8414 §2 forbids a query component in an issuer
identifier, so `https://id.example.com?tenant_id=…` is not a legal issuer and
there is nothing else to put in the parameter. A client that is handed only an
issuer and derives discovery from it therefore always lands on the deployment's
default tenant (`AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID`, or none).

For a browser-based relying party configured by hand that is fine: an operator
pastes the endpoint URLs and the query rides along. For an **MCP** server it is
not, because the MCP specification gives an MCP client exactly one thing — the
`authorization_servers` entry of the RFC 9728 protected-resource metadata — and
that entry is an *issuer*.

**`{root}/t/{tenant_id}` — the path form.** Set
`AXIAM__AUTH__TENANT_ISSUER_PATHS=true` and each tenant gains a second,
query-free issuer identifier:

```
https://id.example.com/t/6f9619ff-8b86-d011-b42d-00c04fc964ff
```

The path is **derived, never configured**. There is no per-tenant issuer
setting: a deployment sets the root issuer and the tenant path follows from it,
which is why the boot check above still insists the root be a bare URL.

**The Shared Signals transmitter needs it on a deployment of more than one
tenant** (D-55). A Security Event Token carries the tenant's issuer as `iss`,
so without per-tenant issuers every tenant's SETs would carry the root issuer
and the same key, and a receiver could not tell one tenant's from another's.
While the flag is off and the deployment holds more than one tenant (counted
across every organization), SSF is inactive for every tenant, exactly as if
`ssf_enabled` were off, and turning `ssf_enabled` on is refused with `400`. The
tenant count is re-read at least once a minute, and at once on the instance that
creates a tenant. A single-tenant deployment keeps the root issuer. See
[contract §32.3 rule 13](../../sdks/CONTRACT.md#§323-server-rules-every-sdk-can-observe-normative).

### The three discovery forms

With the flag set, all three of the conventional ways a client turns an issuer
into a discovery URL are served, and all three return the identical document:

```console
# RFC 8414 §3.1 — insert the well-known segment after the host
$ curl -s https://id.example.com/.well-known/oauth-authorization-server/t/6f9619ff-8b86-d011-b42d-00c04fc964ff

# the same insertion at the OIDC discovery path
$ curl -s https://id.example.com/.well-known/openid-configuration/t/6f9619ff-8b86-d011-b42d-00c04fc964ff

# OpenID Connect Discovery 1.0 §4 — append to the issuer
$ curl -s https://id.example.com/t/6f9619ff-8b86-d011-b42d-00c04fc964ff/.well-known/openid-configuration
```

Three forms because clients disagree about which to derive, and a client that
picked any of them must find AXIAM. They are produced by one function, so they
cannot drift.

The document they return names the tenant issuer and endpoints under it, with
**no** `tenant_id` anywhere:

```console
$ curl -s https://id.example.com/t/6f9619ff-8b86-d011-b42d-00c04fc964ff/.well-known/openid-configuration \
  | jq -r .issuer,.token_endpoint,.jwks_uri
https://id.example.com/t/6f9619ff-8b86-d011-b42d-00c04fc964ff
https://id.example.com/t/6f9619ff-8b86-d011-b42d-00c04fc964ff/oauth2/token
https://id.example.com/t/6f9619ff-8b86-d011-b42d-00c04fc964ff/oauth2/jwks
```

Every OAuth2 endpoint is served under `/t/{tenant_id}` as well as at the root —
the same handlers, the same rate limits, the same behaviour — and the `iss` of
everything a request there mints is the tenant issuer: the access token, the ID
token, the RFC 9207 `iss` authorization-response parameter, and the
Back-Channel Logout token.

### One JWKS, many issuers

`jwks_uri` is re-based on the tenant path, but the key set behind it is the
**same key set** as the root issuer's, byte for byte. RFC 8414 permits an
authorization server to publish one key set for several issuer identifiers, and
AXIAM does: there is one signing key per deployment, not one per tenant.

That has a consequence worth stating plainly, because it is what the
implementation had to defend against. A tenant-`A` token and a tenant-`B` token
are signed by the same key, so **the signature does not say which tenant a token
is for**. AXIAM therefore checks two further things on every request:

* the token's `iss` and its `tenant_id` claim must agree — a token whose issuer
  names tenant `A` and whose claim says `B` is refused outright; and
* the tenant in the request's path must be the tenant the token was minted for
  — a tenant-`A` token presented under `/t/{B}` is refused with `401`, exactly
  as a request with no credential at all is.

Sending `?tenant_id=` on a `/t/{tenant_id}` path is refused with
`invalid_request`, agreeing or not. Two tenant selectors on one request is the
shape a confused-deputy bug takes, and a client that followed the tenant
discovery document never sends one.

### What an MCP server puts in `authorization_servers`

An MCP server publishes RFC 9728 protected-resource metadata naming the
authorization server that fronts it. What goes in `authorization_servers`
depends on which form this deployment serves:

| Mode | `authorization_servers` entry | What the MCP client reaches |
| --- | --- | --- |
| Default (`?tenant_id=`) | `https://id.example.com` | The deployment's default tenant, whatever the MCP server is scoped to |
| `TENANT_ISSUER_PATHS=true` | `https://id.example.com/t/{tenant_id}` | Exactly that tenant |

```jsonc
// The MCP server's /.well-known/oauth-protected-resource, path form
{
  "resource": "https://mcp.example.com",
  "authorization_servers": [
    "https://id.example.com/t/6f9619ff-8b86-d011-b42d-00c04fc964ff"
  ],
  "bearer_methods_supported": ["header"]
}
```

A single-tenant deployment needs none of this: one issuer already means one
tenant, and `AXIAM__AUTH__OAUTH2_DEFAULT_TENANT_ID` makes the bare document
name it. Turn the flag on when **one** AXIAM fronts MCP servers for **more than
one** tenant.

### With it off

Nothing above is mounted. `/t/{tenant_id}/…` and the two
`/.well-known/…/t/{tenant_id}` paths do not exist, no token can carry a tenant
issuer, and the only issuer AXIAM accepts on an inbound token is the root one —
which is what it accepted before this setting existed. The `?tenant_id=`
documents are byte-identical either way.

## Session revocation feed (optional, T-39 / T-143)

`AXIAM__AUTH__REVOCATION_FEED_ENABLED` — default `false`.

An AXIAM access token is self-contained and valid for up to fifteen minutes,
and an SDK route guard verifies it locally. A logout, a role removal or an
account disable therefore does not reach a token already in a caller's hands
until it expires. The documented answer has been "route the decision through
gRPC introspection instead" — correct, and a network round trip **per
request**, which is why integrations rarely take it.

With this set, the server publishes `GET /oauth2/revocations`:

```json
{ "alg": "SHA-256", "issued_at": 1757664000, "ttl": 900,
  "revoked": ["i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ"] }
```

An SDK guard that polls it (contract §10.4, opt-in on that side too) rejects a
revoked session within **one poll interval** instead of one token lifetime.

**What the document does and does not disclose.** An entry is the base64url
SHA-256 of a session id — never an id, a subject, a tenant or a timestamp. A
session id is not a subject, so the feed says neither who was revoked nor how
many people are behind the entries; and a reader who does not already hold a
`sid` learns nothing they can use, because a UUIDv4 preimage space is not
walkable. That is a non-enumerability argument, not a guarantee, and it is
stated that way on purpose.

**What bounds it.** An entry is published for exactly one access-token
lifetime, after which every token naming that session has expired on its own
`exp` and the entry proves nothing. So the document's size tracks your
revocation rate over fifteen minutes and never your history. It is filtered on
read as well as swept: a sweep that falls behind makes the table large, never
the document wrong.

**What it is not.** It is not a control. A guard that cannot fetch the feed
behaves exactly as it does without it — the contract requires that, and it is
what stops a network blip from becoming an outage. The feed can only ever turn
an accept into a reject, never the reverse, and every local verification rule
still runs first and still decides.

**With it off** — the default — the route is not mounted, no `revoked_session`
row is written, and the deployment is byte-identical to one built before the
feed existed.

Turn it on where sign-out has to take effect faster than fifteen minutes and
routing every authorization decision through gRPC is too expensive. Leave it
off if neither is true: it is one more public endpoint, and an endpoint nobody
polls narrows nothing.

## Audit collection minimisation (optional, T-110)

`AXIAM__AUDIT__MINIMISE` — default `false`.

The audit log is append-only by design, which is in direct tension with the
Art. 17 erasure path AXIAM also offers: what is written into it cannot later be
removed, only aged out. `AXIAM__AUDIT_RETENTION_DAYS` bounds the *retention*
side (default 730 days, the table's only deletion path). This bounds the
**collection** side, which was previously not configurable at all.

With it on, two fields are reduced immediately before the append — after it
there is no second chance, by construction:

| Field | Becomes | Kept for |
|---|---|---|
| `ip_address` | the `/24` (IPv4) or `/48` (IPv6) prefix, e.g. `203.0.113.42` → `203.0.113.0/24` | seeing a pattern, correlating a burst, answering "was this the office" |
| `metadata.user_agent`, where a producer sets one | a coarse family — `Firefox`, `Chrome`, `curl`, `other` | the part an investigation reads |

An address that does not parse is **dropped** rather than written through: a
value that cannot be parsed cannot be shown to have been minimised, and passing
it would be a silent hole in the control. A `host:port` string is handled, so
the common `realip_remote_addr` shape does not lose a field for no reason, and
a v4-mapped v6 address is minimised as the v4 address it is.

**What it does not touch, deliberately.** The structured metadata domain
producers write is accountability evidence other controls depend on — the
client, profile and disposition on a refresh-token replay (T-254), the names of
released claims (T-241), the provider and external subject on a JIT provision
(T-161). Dropping it would weaken three controls to narrow one, and none of it
is request metadata. The request-audit middleware itself records only
`http_status` and `authenticated`, which is pinned by a test rather than left
to habit.

**Erasure and export are unaffected.** The Art. 17 scrub clears `ip_address`
outright, so a truncated value is erased by exactly the same statement as a
whole one. The Art. 15 export's `audit_entries` section reads `action`,
`outcome`, `timestamp` and `resource_id` and never the address, so a data
subject's inventory is identical either way.

**Deployment-wide, and deliberately not per tenant.** Audit is an
accountability control the deployment relies on *including against a tenant
administrator*; a per-tenant switch would let a tenant weaken the evidence used
to investigate that tenant. It is the same argument that makes
`sensitive_scopes_enabled` disable-only for a tenant, applied to a control
where the tenant is a possible subject rather than a possible victim.

Off by default because turning it on reduces forensic precision, and that is a
lawful-basis judgement to make deliberately rather than inherit. **Both states
are logged at startup**, exactly as retention is: an operator opening an
incident needs to know, before they start reading rows, whether the addresses
in them are whole.

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

## Secrets

- [**Secrets and HashiCorp Vault**](vault.md) — where AXIAM's ten long-lived
  secrets come from, what each one costs to lose, running Vault for them, and
  the AWS/GCP/Azure/PKCS#11 alternatives. Read §5 before going to production:
  auto-unseal is the step most often deferred and the one that pages you at 3am.
