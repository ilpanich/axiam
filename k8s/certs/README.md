# Certificate examples (cert-manager)

**K8S-F4.** Three Secrets are *consumed* by the manifests in `k8s/` and
*produced* by nothing in it:

| Secret | Consumed by | Keys the consumer reads |
|---|---|---|
| `vault-tls` | `k8s/vault/statefulset.yml`, via the `tls` volume; `vault.hcl` names the two files | `tls.crt`, `tls.key` |
| `rabbitmq-broker-tls` | `k8s/rabbitmq/statefulset.yml` (whole Secret) and `k8s/server/deployment.yml` (the `ca.crt` key only) | `tls.crt`, `tls.key`, `ca.crt` |
| `axiam-server-tls` | `k8s/server/deployment.yml`, the server's own TLS 1.3 listener | `tls.crt`, `tls.key` |

So **cert-manager is a requirement of the shipped manifests, not an addition**.
Without those Secrets the Vault and RabbitMQ pods stay `ContainerCreating`
forever and the server cannot terminate TLS. The RabbitMQ manifest's own comment
already named cert-manager as the intended issuer; this directory is that
intention written down.

## Why this directory is not in `k8s/kustomization.yml`

Every file here is a cert-manager custom resource. Applying them to a cluster
without cert-manager's CRDs fails with `no matches for kind "Certificate"`, and
a base kustomization that cannot be applied to a bare cluster is worse than one
that leaves a documented gap. Apply them as a second step, after cert-manager is
installed and its webhook is serving:

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml
kubectl -n cert-manager wait --for=condition=Available deploy --all --timeout=300s
kubectl apply -k k8s/
kubectl apply -f k8s/certs/          # issuers first, then the leaves
```

`infra/rpi5-k3s/` does all of this for you on a single-node k3s Pi, with
OpenTofu ordering the steps; see
[`docs/deployment/rpi5-k3s.md`](../../docs/deployment/rpi5-k3s.md).

## Bring your own CA instead

Nothing here is required. AXIAM needs the three Secrets to exist with those
keys; it does not care who made them. To issue them from a CA you already run,
delete this directory and create the Secrets yourself — `kubectl create secret
tls` for the two-key ones, plus `ca.crt` for the broker. What you give up is
renewal, which for a broker certificate matters: a silently expired
`rabbitmq-broker-tls` takes the whole async plane down, and AXIAM has no
verification-skip option to fall back on.

## What is here

| File | Creates |
|---|---|
| `00-private-ca.yml` | `ClusterIssuer/axiam-selfsigned`, the root `Certificate/axiam-ca` and `ClusterIssuer/axiam-ca` — the in-cluster CA every internal leg is issued from |
| `10-internal-leaves.yml` | `Certificate`s for `vault-tls`, `rabbitmq-broker-tls`, `axiam-server-tls` and `axiam-ingress-client` |
| `20-public-acme.yml` | An example ACME `ClusterIssuer` (HTTP-01 through ingress-nginx) for the **public** leaf the Ingress serves — a different CA from the one above, on purpose |

## Why two CAs and not one

The public leaf (what a browser sees) and the internal leaves (what the ingress,
Vault, RabbitMQ and the server present to each other) are issued by different
authorities, and that is the design rather than an accident:

* A public CA will not issue for `vault.axiam.svc.cluster.local`. It is not a
  name anyone can prove control of, and it should not be.
* ingress-nginx verifies an upstream with `proxy-ssl-verify: "on"` +
  `proxy-ssl-secret`, and that Secret must hold a **client** keypair as well as
  `ca.crt`. Verifying the backend against the public roots would mean minting a
  client certificate for the ingress from nowhere. With a private CA the ingress
  simply gets its own leaf from the same issuer.

`claude_dev/public-backend-tls-design.md` §3.1 anticipated exactly this: it says
the public-leaf reuse on the Compose path was a Pi-without-a-CA expedient, and
that on Kubernetes "a service mesh or cert-manager" would issue the backend
certificate.

## Renewal semantics, which differ per consumer

cert-manager rewrites the Secret; what happens next is not uniform:

| Consumer | Picks up a renewed leaf | Why |
|---|---|---|
| `axiam-server` | **By itself, within the hour.** | The kubelet refreshes a Secret volume within its sync period, and the server re-`stat`s its leaf every `AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS` (default 3600) and swaps it behind an `ArcSwap` rustls consults per handshake. No restart, no dropped request. |
| ingress-nginx | By itself. | The controller watches the Secret. |
| Vault | **Needs a pod restart.** | It reads `tls_cert_file` at listener start and has no reload path. |
| RabbitMQ | **Needs a pod restart.** | Same. |

Two consequences the manifests here encode. **Do not mount these Secrets with
`subPath`** — a `subPath` mount is not refreshed by the kubelet, so the server's
poll would re-read a file that never changes and the certificate would expire
under a running process. And the Vault and RabbitMQ `Certificate`s are given a
**one-year** duration rather than the 90 days used elsewhere, so their
restart-requiring renewal is a scheduled yearly event instead of a quarterly
surprise.
