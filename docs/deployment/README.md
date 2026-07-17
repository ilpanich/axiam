# AXIAM Deployment Guide

**Milestone:** v1.2 (MVP Release Hardening) — Beta
**Last verified:** 2026-07-06

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
| `AXIAM__AUTH__PEPPER` | Password pepper (plain string) prepended before Argon2id hashing. Generate a long random string, e.g. `openssl rand -base64 32`. |

Set every value to a placeholder such as `<set-in-secret-manager>` in any
example or template you author — never commit real key material, and never
reuse the same value across environments.

The AMQP connection string is not itself a `secret.yml` key; it is assembled
from `RABBITMQ_DEFAULT_USER` / `RABBITMQ_DEFAULT_PASS` (see
[`k8s/rabbitmq/secret.yml`](../../k8s/rabbitmq/secret.yml)) into
`AXIAM__AMQP__URL` at the deployment layer (see how
`docker-compose.prod.yml` does this for the Compose path).

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
