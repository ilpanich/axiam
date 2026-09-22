# Running AXIAM on a Raspberry Pi 5 with k3s, at `axiam-iam.duckdns.org`

**Status:** operator runbook — written 2026-09-16 against `1.0.0-beta15`.
**Audience:** one person deploying AXIAM on their own Pi, on Kubernetes rather
than Compose, provisioned with OpenTofu.

Everything below is derived from what is in this repository at this commit.
Where the code and a plausible expectation disagree, the code wins and the
disagreement is called out.

The Compose version of this deployment is
[`claude_dev/rpi5-prod-google-federation-guide.md`](../../claude_dev/rpi5-prod-google-federation-guide.md)
— "the Pi guide" below. This file is its k3s counterpart and links to it rather
than copying it: §3, §9–§12 are unchanged and live there. The topology and the
reasoning behind every choice in it is
[`claude_dev/public-backend-tls-design.md`](../../claude_dev/public-backend-tls-design.md).

---

## ⚠ What has never been run

This guide, the scripts under `infra/rpi5-k3s/` and the OpenTofu stages were
authored in an environment with **no Kubernetes cluster, no Docker daemon, and a
proxy that blocks both Terraform provider registries.** The tree is the product
of static checks, not of a deployment. Everything below was verified as stated:

| Checked | How | Result |
|---|---|---|
| Manifests render | `kubectl kustomize` on `k8s/` and `infra/rpi5-k3s/overlay/` | base 29 objects, overlay 25 (26 with gRPC on) |
| Manifest schemas | `kubeconform -strict` against upstream schemas | 29/29 and 25/25 valid |
| cert-manager custom resources | `kubeconform -strict` against the upstream CRD schemas | 9/9 valid |
| Pod Security `restricted` | a static re-implementation of the profile's field list, run over both renders | 5/5 admit; it reproduces the pre-fix Vault failure, so it is not vacuous |
| Overlay vs base | every difference in the rendered diff mapped to a finding or a decision | reviewed line by line |
| Shell | `shellcheck -S warning` and `bash -n` on every script | clean |
| HCL formatting | `tofu fmt -check -recursive` | clean |
| Pinned versions exist | each release artifact fetched directly | k3s, kubectl, OpenTofu, cert-manager, ingress-nginx, six providers |
| Pinned images are arm64 | manifest lists resolved from the real registries | all publish `linux/arm64` |
| ingress-nginx annotations | read out of the chart's own docs and `nginx.tmpl` at the pinned version | confirmed, and one of them corrected this guide (§6.2) |
| Trivy config scan | `trivy config --severity HIGH,CRITICAL` on `infra/` and `k8s/`, and on the tree as it was before this branch | `infra/` clean; `k8s/`'s one HIGH (KSV-0109 on the ConfigMap) is **pre-existing** — it reproduces identically at `d20293a` |
| Doc links | `scripts/check-doc-links.sh` | clean |

**And these were NOT run, because they cannot be without hardware. Run them on
the Pi first, and expect to find something.**

| Not executed | Why | What to do |
|---|---|---|
| `tofu init`, `tofu validate`, `tofu plan` | `registry.opentofu.org` and `registry.terraform.io` both answer **403** through the authoring proxy, so no provider could be downloaded | `run.sh <stage> init` then `run.sh <stage> plan` on the Pi, for all three stages, **before** your first apply. The HCL has never been semantically validated — only formatted. Read the plan output rather than skimming it. |
| Any `kubectl apply` | no cluster | The admission checks in §12 are the substitute, and they are static |
| `helm template` / `helm install` | `get.helm.sh` and the helm GitHub releases are both blocked | Stage 10's chart values have never been rendered. `helm template ingress-nginx ingress-nginx/ingress-nginx --version 4.15.1 -f <values>` on the Pi is worth one minute before the apply |
| `.terraform.lock.hcl` | cannot be generated without the registries | The first `init` on the Pi writes it. Commit it, or back it up with the state |
| The scripts, end to end | they drive a real cluster, a real Vault, a real Let's Encrypt | They are `shellcheck`-clean and their guards were exercised; their happy paths were not |
| `05-verify.sh` §11 | needs two devices on different public networks | §6.2 below. It is an acceptance step, not a suggestion |

Nothing in this document claims to have been verified beyond that table.

---

## 0. What changes from the Compose Pi guide

| Pi guide (Compose) | Here (k3s) | Why |
| --- | --- | --- |
| Caddy on the host, systemd | **ingress-nginx**, a hostNetwork DaemonSet in the cluster | `k8s/ingress.yml` is already `ingressClassName: nginx` and two NetworkPolicies select the namespace `ingress-nginx` by name. Adopting Traefik would mean rewriting all of it. §2 |
| certbot on the host owns ACME; a deploy hook copies the leaf | **cert-manager** owns ACME; the leaf lives in a Secret both the Ingress and the pod read | Same principle — one ACME client, two consumers — expressed the Kubernetes way. Renewal needs no hook. §4 |
| Backend serves the **public** Let's Encrypt leaf | Backend serves a leaf from an **in-cluster private CA** | `public-backend-tls-design.md` §3.1 says the public-leaf reuse was a Pi-without-a-CA expedient and that cert-manager is what Kubernetes would do. §4.2 |
| `just prod-up` mints credentials and runs a laptop Vault ceremony | **OpenTofu** mints credentials into Secrets; the ceremony is a **human** script, then OpenTofu configures mount, policy and token | §5, §7 |
| `~/axiam-up.sh` + `axiam-stack.service` | Nothing. k3s is a systemd unit and pods restart themselves | §8 |
| `TRUSTED_HOPS=0` because Caddy is the one proxy | **Still `0`** — but for a different reason than the Pi guide gives | §6.2. The value is the same; the derivation is not, and that matters when you change the topology |
| gRPC optional via a Caddy `handle` on 443 | gRPC optional via a second Ingress with `backend-protocol: GRPCS`, same three-service allowlist | §14 |
| DuckDNS, router, the five IdPs, `/auth/sso/callback`, bootstrap, federation configs, WebAuthn and issuer settings | **Unchanged** | None of it is about the container runtime |

### Is Kubernetes on a Pi 5 a reasonable thing to do? Yes — with k3s

`docker-compose.prod.yml` says in its own header that it is not the production
path and that `k8s/` is; the Pi guide repeats it in §17. Moving the Pi to
Kubernetes is moving it onto the path this repository already calls supported.

The distribution matters more than the fact of it. **k3s**: one static arm64
binary, a systemd unit, ~500–700 MB idle, a real kubelet on the host network so a
public listener on 80/443 is an ordinary Pod rather than a tunnel. **minikube is
not an option here** — the cluster runs inside a container or VM on the Pi,
public ingress needs `minikube tunnel`, it does not come back cleanly after a
power cut, and nothing in it is designed to face the internet. MicroK8s works and
is heavier, and its add-ons pin versions you do not choose. kubeadm is correct and
is more machinery than one node is worth.

---

## 1. What you need before you start

**Hardware / OS**

- Raspberry Pi 5, **8 GB required** — not recommended, required. The k3s control
  plane takes 500–700 MB before ingress-nginx (~150 MB), cert-manager (~120 MB
  across three pods), Vault, RabbitMQ, SurrealDB and axiam-server. The Pi guide
  calls 4 GB "tight" for Compose; with a control plane on top it is not enough.
- **Boot from NVMe or SSD.** SurrealDB's `surrealkv` engine on an SD card is
  miserable, and now the `local-path` PVCs for RabbitMQ (5Gi) and Vault (1Gi)
  share the same device.
- Raspberry Pi OS (64-bit) or Ubuntu Server 24.04 arm64. **64-bit is mandatory**:
  the released images are `linux/amd64` and `linux/arm64` only.
- ~25 GB free. Container images alone are several GB before the 16Gi of PVCs.

**Two things Raspberry Pi OS needs that k3s will not do for itself**, both
handled by `00-host-prepare.sh` and both requiring a reboot:

- `cgroup_memory=1 cgroup_enable=memory` on the kernel command line. Without it
  the kubelet refuses to start, with a message about the memory cgroup that
  reads like a k3s bug.
- **Swap off.** Raspberry Pi OS enables a 200 MB `dphys-swapfile` by default.
  The kubelet fails to start with swap enabled unless told to tolerate it, and
  tolerating it on a node holding decrypted secrets is the wrong trade.

**Network** — unchanged from the Pi guide §1:

- The DuckDNS name pointing at your public IP, kept current by the updater (§3).
- Router forwards **TCP 80 and 443** to the Pi, and nothing else. 80 is needed
  for the HTTP-01 challenge.
- **Do not forward** 8090, 50051, 8200, 5671, 15672 or 6443. Publishing gRPC
  (§14) does not change this — that route arrives on 443 like everything else.

**Accounts** — one or more of Google, GitHub, Facebook, Apple Developer
(**paid**) and Microsoft Entra. Plus the repository, at a released tag:

```bash
git clone https://github.com/ilpanich/axiam.git ~/axiam
cd ~/axiam
git checkout v1.0.0-beta15
```

**Deploy a tag, not `main`.** The overlay pins `1.0.0-beta15` and the images
carry the released version with the leading `v` stripped. Pre-releases get **no**
moving tags — no `latest`, no `1.0` — so nothing drifts under you. On 2026-09-16
`ghcr.io/ilpanich/axiam/server:1.0.0-beta15` and `.../frontend:1.0.0-beta15` both
resolved to a manifest list carrying `linux/amd64` and `linux/arm64`.

**Everything this deployment pins** is in `infra/rpi5-k3s/scripts/versions.env`:
k3s `v1.36.1+k3s1`, kubectl `v1.36.1`, OpenTofu `1.12.6`, cert-manager
`v1.21.2`, ingress-nginx chart `4.15.1`. k3s is a patch release of the previous
Kubernetes minor, deliberately: the `.0` of a new minor on the only node you have
is not where to discover a regression.

You do **not** need a Rust toolchain, Docker, or `just`.

---

## 2. How the pieces fit together

```
                          Internet
                             │ 443 (and 80 for HTTP-01)
                             │ router forwards ONLY these two to the Pi
                             ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ Raspberry Pi 5 · 64-bit OS · k3s (single node)                   │
   │                                                                  │
   │  ns ingress-nginx                                                │
   │  ┌────────────────────────────────────────────────────────────┐  │
   │  │ ingress-nginx controller — DaemonSet, hostNetwork,          │  │
   │  │ listens on the node's 80/443. The ONLY public listener.     │  │
   │  │ TLS: Secret axiam-public-tls (cert-manager, Let's Encrypt)  │  │
   │  └───────┬──────────────────────────────┬─────────────────────┘  │
   │          │ /            (HTTP)          │ /api /oauth2 /.well-known
   │          ▼                              │ (HTTPS, verified against
   │  ns axiam                               │  the in-cluster CA)
   │  ┌───────────────┐    ┌─────────────────▼──────────────────┐     │
   │  │ axiam-frontend│    │ axiam-server ×1                    │     │
   │  │ nginx, SPA    │    │ REST :8090 TLS1.3 · gRPC :50051    │     │
   │  │ :8080         │    │ leaf: Secret axiam-server-tls      │     │
   │  └───────────────┘    └──┬──────────┬──────────┬───────────┘     │
   │                          │8000      │5671 amqps│8200 https       │
   │                   ┌──────▼───┐ ┌────▼─────┐ ┌──▼────────────┐    │
   │                   │ surrealdb│ │ rabbitmq │ │ vault (Raft)  │    │
   │                   │ surrealkv│ │ TLS 1.3  │ │ TLS 1.3       │    │
   │                   │ PVC 10Gi │ │ PVC 5Gi  │ │ PVC 1Gi       │    │
   │                   └──────────┘ └──────────┘ └───────────────┘    │
   │                                                                  │
   │  ns cert-manager: cert-manager · ClusterIssuers:                 │
   │    letsencrypt-http01 · letsencrypt-staging                      │
   │    axiam-selfsigned → axiam-ca (every internal leg)              │
   │                                                                  │
   │  host: duckdns cron · k3s.service · OpenTofu + state (0700)      │
   └──────────────────────────────────────────────────────────────────┘

   Not routed: /health, /ready, /health/jobs, gRPC (unless §14).
   Not forwarded at the router: anything but 80 and 443.
```

Four consequences that matter for everything below.

1. **One origin.** The SPA at `https://axiam-iam.duckdns.org/` and the API at
   `…/api` are the same scheme, host and port, so no browser ever issues a
   preflight. `AXIAM__SERVER__CORS_ALLOWED_ORIGINS` stays **empty**.
2. **One proxy in front of the backend.** That is what makes `TRUSTED_HOPS=0`
   correct — see §6.2 before changing anything about the edge.
3. **The backend terminates its own TLS.** No AXIAM credential crosses the pod
   network in cleartext. A pod network on a single node is the Docker bridge with
   a different name.
4. **Health endpoints are deliberately not public.** `/health/jobs` reports
   per-job scheduler state — names, last-run times, consecutive failures — a free
   map of what you run and what is broken in it. They land on the SPA route and
   return `index.html`.

---

## 3. DuckDNS

Unchanged. **[Pi guide §3](../../claude_dev/rpi5-prod-google-federation-guide.md#3-duckdns).**
The updater is a host cron job and has nothing to do with Kubernetes.

---

## 4. Certificates

Two certificate authorities, and the split is the design rather than an accident.

### 4.1 The public leaf

`cert-manager` watches the two Ingress objects, sees `spec.tls` and the
`cert-manager.io/cluster-issuer` annotation, and creates a `Certificate` for the
Secret named there. The HTTP-01 challenge is solved through the same controller,
which works because it is a hostNetwork DaemonSet bound to the node's port 80 and
your router forwards 80 to the Pi.

**Use `letsencrypt-staging` first, every time.** Production rate limits are per
registered domain per week, and five failed orders is a lockout that outlasts the
afternoon you have to debug in. Staging issues an untrusted certificate from the
same code path — exactly what you want to be wrong about. Switch by setting
`acme_issuer` and re-applying; the overlay's annotation is the only thing that
changes.

If your ISP blocks inbound 80, HTTP-01 cannot work and no configuration on this
side changes that. Your options, in order of honesty:

- **A DNS-01 solver.** cert-manager has no built-in DuckDNS solver. A community
  webhook exists and is arm64-buildable; this deployment deliberately does **not**
  ship it, because pinning a third-party image by digest and keeping it current is
  a commitment, and an unpinned one is worse. If you adopt it, pin the digest.
- **A manual DNS-01 certificate**, renewed by you. Workable and easy to forget.
- **Ask your ISP to unblock 80.** Often the fastest path.

### 4.2 The internal legs, and why they are a private CA

The ingress verifies the backend with `proxy-ssl-verify: "on"` +
`proxy-ssl-secret`, and **that Secret must hold a client keypair as well as
`ca.crt`**. Verifying against the public roots would mean minting a client
certificate for the ingress from nowhere. With `ClusterIssuer/axiam-ca` the
ingress simply gets its own leaf from the same issuer, and `ca.crt` is an anchor
it already trusts.

`public-backend-tls-design.md` §3.1 anticipated this: it says the public-leaf
reuse on the Compose path was a *Pi-without-a-CA* expedient and that on Kubernetes
"a service mesh or cert-manager" would issue the backend certificate.

Four leaves, all from `axiam-ca`:

| Secret | Presented by | Verified by |
|---|---|---|
| `axiam-server-tls` | the backend's REST (and gRPC) listener | ingress-nginx, via `proxy-ssl-name: axiam-server.axiam.svc` |
| `vault-tls` | Vault's listener | the server, via `AXIAM__AUTH__VAULT_CA_CERT_PATH` |
| `rabbitmq-broker-tls` | the broker | the server, via `AXIAM__AMQP__TLS__CA_CERT_PATH` — only `ca.crt` is projected into the server pod |
| `axiam-ingress-client` | ingress-nginx, upstream | the server ignores it (`client_auth: off`), but the controller will not accept a Secret without it |

`vault-tls` also carries **`127.0.0.1` as an IP SAN**. The Vault pod sets
`VAULT_ADDR=https://127.0.0.1:8200`, so the entire unseal ceremony runs through
`kubectl exec` against that literal address. Without the IP SAN the only way past
it would be `-tls-skip-verify` on the one command that hands you your unseal
shares, which is the last place to turn verification off.

### 4.3 Renewal, which is not uniform

cert-manager rewrites the Secret. What happens next depends on the consumer:

| Consumer | Picks up a renewal | Why |
|---|---|---|
| `axiam-server` | **by itself, within the hour** | the kubelet refreshes a Secret volume within its sync period, and the server re-`stat`s its leaf every `AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS` (3600) and swaps it behind an `ArcSwap` rustls consults per handshake. No restart, no dropped request |
| ingress-nginx | by itself | it watches the Secret |
| **Vault** | **needs a pod restart** | it reads `tls_cert_file` at listener start and has no reload path |
| **RabbitMQ** | **needs a pod restart** | same |

Two consequences are baked into the manifests. The server's leaf volume is **not**
mounted with `subPath` — a `subPath` mount is not refreshed by the kubelet, so the
poll would re-read a file that never changes and the certificate would expire
under a running process. And the Vault and RabbitMQ leaves get a **one-year**
duration rather than ninety days, so their restart-requiring renewal is a
scheduled annual event rather than a quarterly surprise.

**Write the Vault one in your calendar.** A Vault restart without auto-unseal
(§7.1) is a human with three shares, and "the certificate renewed" is not the
first explanation anyone reaches for when the whole site 502s.

---

## 5. Bring the stack up

```bash
cd ~/axiam
cp infra/rpi5-k3s/tofu/example.tfvars infra/rpi5-k3s/tofu/10-platform/10-platform.auto.tfvars
$EDITOR infra/rpi5-k3s/tofu/10-platform/10-platform.auto.tfvars   # acme_email
# and trim a copy for each of the other two stages — an unknown variable in an
# auto.tfvars file is an error, not a warning.

infra/rpi5-k3s/scripts/00-host-prepare.sh     # exits 10 if a reboot is needed
sudo reboot                                    # if it said so
infra/rpi5-k3s/scripts/01-install-k3s.sh

infra/rpi5-k3s/run.sh 10-platform init && infra/rpi5-k3s/run.sh 10-platform plan
infra/rpi5-k3s/run.sh 10-platform apply

infra/rpi5-k3s/run.sh 20-axiam init && infra/rpi5-k3s/run.sh 20-axiam plan
infra/rpi5-k3s/run.sh 20-axiam apply
```

**Run `init` and `plan` separately the first time, and read the plan.** The HCL
in this repository has never been through `tofu validate` (see the table at the
top), so your `plan` is the first semantic check it has ever had.

At this point the server pod sits in `CreateContainerConfigError` saying
`secret "axiam-vault-token" not found`. **That is correct.** It cannot serve a
login before Vault is initialised and seeded.

```bash
infra/rpi5-k3s/scripts/02-vault-ceremony.sh    # §7 — a human, five shares

read -rs VAULT_TOKEN && export VAULT_TOKEN
infra/rpi5-k3s/run.sh 30-vault-config init
infra/rpi5-k3s/run.sh 30-vault-config apply
# then revoke the root token, exactly as run.sh tells you to
unset VAULT_TOKEN

read -rs AXIAM_ADMIN_PASSWORD && export AXIAM_ADMIN_PASSWORD
infra/rpi5-k3s/scripts/03-axiam-bootstrap.sh
infra/rpi5-k3s/scripts/05-verify.sh
```

### 5.1 The settings you must supply

All of them are in `infra/rpi5-k3s/overlay/configmap-env.yml`, already filled in
for `axiam-iam.duckdns.org`. Change the hostname there **and** in
`overlay/ingress-host.yml` — four live occurrences in each, eight in all, and
each one fails differently when it disagrees:

```bash
grep -rn axiam-iam.duckdns.org infra/rpi5-k3s/overlay/
```

The long form of what each does is
**[Pi guide §5.2](../../claude_dev/rpi5-prod-google-federation-guide.md#52-the-settings-you-must-supply)**;
the short form is that `AXIAM_WEBAUTHN_RP_ID` cannot be changed after passkeys
are enrolled, `AXIAM_WEBAUTHN_RP_ORIGIN` must match the address bar byte for byte,
`AXIAM__AUTH__OAUTH2_ISSUER_URL` is what Apple and every SAML IdP build their
redirect URIs from, and `AXIAM_BOOTSTRAP_ADMIN_EMAIL` is a fail-closed gate.

**Note the double underscore.** `AXIAM__DB__URL`, not `AXIAM_DB_URL`. Six names
break the pattern because they are read with `std::env::var` rather than through
the config layer — `AXIAM_BOOTSTRAP_ADMIN_EMAIL`, `AXIAM_HEALTHCHECK_URL`,
`AXIAM_HEALTHCHECK_CA_FILE`, `AXIAM__RATE_LIMIT__TRUSTED_HOPS`,
`AXIAM__GRPC_TLS_CERT_PATH` and `AXIAM__GRPC_TLS_KEY_PATH` — and a misspelling in
any of them is silence, not an error.

`AXIAM_HEALTHCHECK_CA_FILE` is usually unnecessary: the `healthcheck`
subcommand's scheme follows the listener and, on a direct-TLS deployment, it
trusts the server's own `AXIAM__SERVER__TLS__CERT_PATH` chain. Set it when that
file holds a CA-issued leaf without its issuer beside it. See
[the deployment guide](README.md#container-healthcheck-axiam-server-healthcheck).

### 5.2 Credentials are honoured only on the first boot of an empty volume

`infra/rpi5-k3s/tofu/20-axiam/credentials.tf` mints the SurrealDB and RabbitMQ
passwords with `random_password` and writes them into the Secrets `k8s/` ships
blank. SurrealDB records its root user the first time it starts on an empty
`/data`; RabbitMQ does the same for its user, password and vhost.

**After that, changing one does not rotate anything — it breaks
authentication.** The ways back are `rabbitmqctl change_password` / a SurrealDB
`DEFINE USER`, or deleting the PVC and everything in it. Every credential
resource therefore carries `ignore_changes = all` and `prevent_destroy = true`,
and `run.sh` refuses `destroy` on stage 20 without an explicit flag. The
lifecycle block refuses even with the flag; an operator who genuinely means it
edits that file, which is a diff somebody can review.

---

## 6. Three settings worth understanding, not just copying

### 6.1 Why the backend has a certificate at all

Because the alternative is cleartext. With `AXIAM__SERVER__TLS__ENABLED=false`
every password on its way to `/api/v1/auth/login`, every session cookie and every
OAuth2 client secret crosses the pod network in plaintext, readable by anything
that can capture on the node or join the pod network. On a Pi that also runs your
other workloads, that is not hypothetical.

### 6.2 `TRUSTED_HOPS`, and a correction to how the Pi guide derives it

**The value is `0`. The reason is not the one the Pi guide gives**, and the
difference matters the moment you change the edge.

The Pi guide §6.3 says every proxy appends the address it received from
(`proxy_add_x_forwarded_for`) and names ingress-nginx as doing the same.
**It does not.** At chart `4.15.1` the controller's `nginx.tmpl` emits

```
{{ if and $all.Cfg.UseForwardedHeaders $all.Cfg.ComputeFullForwardedFor }}
proxy_set_header  X-Forwarded-For  $full_x_forwarded_for;
{{ else }}
proxy_set_header  X-Forwarded-For  $remote_addr;
```

and stage 10 sets `use-forwarded-headers: "false"`. So ingress-nginx **replaces**
`X-Forwarded-For` with the socket peer rather than appending to whatever arrived.
The server therefore reads a single-entry header holding the real client, and
`TRUSTED_HOPS=0` selects it.

That is a *stronger* property than the Compose path's: a client that sends its
own `X-Forwarded-For` has it discarded outright, not merely out-voted by an entry
appended to its right.

Two things follow, and both are load-bearing:

- **hostNetwork on the controller is not a convenience.** `$remote_addr` is the
  real client only because the controller binds the node's 80/443 directly. Put
  k3s's ServiceLB (klipper-lb, a DaemonSet of iptables-DNAT pods), MetalLB or a
  NodePort in front and `$remote_addr` becomes that hop's address — one
  rate-limit bucket for the whole internet, `/auth/login` included, which is
  deliberately always keyed per-IP so an attacker cannot lock out a victim.
  `01-install-k3s.sh` passes `--disable servicelb` for this reason.
- **`use-forwarded-headers` must stay `"false"`.** Set it to `"true"` and nginx
  passes a client's own header through, and a client picks its own bucket per
  request. If something you control genuinely does sit in front of this
  controller, then `TRUSTED_HOPS` is no longer 0 — re-derive it.

`05-verify.sh` checks both of those. What it cannot check is the thing that
matters:

> **Run this from two devices on different public networks — one on mobile
> data.** It is an acceptance step, not a suggestion.

```bash
for i in $(seq 1 40); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST \
    https://axiam-iam.duckdns.org/api/v1/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"org_slug":"nope","username":"nope","password":"nope"}'
done; echo
```

You should see `401`s turning into `429` **per source address**. If the second
device is throttled the instant the first one is, they are sharing a bucket and
the value is wrong for your topology.

### 6.3 Why the OpenTofu state is a secret

Stage 20's state holds the SurrealDB root password and the RabbitMQ password
(inside the AMQP URL). Stage 30's holds the server's Vault token — a bearer
credential for a Vault containing the OPAQUE setup key, the auth pepper and the
JWT signing key. OpenTofu writes all of it in cleartext unless you turn on state
encryption.

`run.sh` keeps the state outside the repository, in `~/axiam-infra/state/` at
mode 0700, and `.gitignore` covers the patterns anyway.
`infra/rpi5-k3s/tofu/encryption.tofu` is the encryption block, commented out with
instructions — including the one that bites: migrating an existing plaintext
state needs `enforced = false` for one apply, and **back it up first**, because an
encrypted state whose passphrase is lost is a state you no longer have and stage
20 will not re-mint credentials a live datastore has already recorded.

The passphrase is held like an unseal share: **off the Pi**. If it sits in a file
next to the state, you have encrypted the state against someone who steals the
backup and nobody else — a real threat model, but say out loud that it is the one
you chose.

**No secret is ever a tofu variable.** Every value in a `.tfvars` file ends up in
the state; the Vault root token goes in the environment of one command, and the
passphrase in `TOFU_ENCRYPTION_PASSPHRASE`.

---

## 7. Vault

### 7.1 Auto-unseal first — the decision nobody should defer

Without it, every Vault restart — a power cut, an `apt upgrade`, an OOM kill, a
k3s upgrade — leaves Vault sealed and `axiam-server` crash-looping, because it
reads every secret out of Vault before it can serve a single login. The pod will
keep restarting for as long as it takes a human with three of five shares to
arrive.

Vault OSS's seal types all need something **outside the box**. `pkcs11` (a TPM or
HSM) is Vault **Enterprise** only, whatever hardware the Pi has. The realistic
choices are a cloud KMS or a second Vault that is already unsealed elsewhere; the
Pi guide §7.1 prices them, and GCP Cloud KMS at about $0.06/key/month is the
cheapest by an order of magnitude.

`infra/rpi5-k3s/overlay/vault-seal.yml` is one file to edit: the `seal` stanza,
the credentials Secret mount, and — the step everyone misses — **the egress
NetworkPolicy**, without which Vault starts, cannot reach the KMS, and stays
sealed behind a timeout that reads like a credentials problem.

If you will do none of these, write it down in your own notes: **you are running
a manually-unsealed Vault, every reboot needs a human with three shares, and this
is not a production deployment.** That is a legitimate home-lab choice. What is
not legitimate is leaving the shares on the box and calling the problem solved.

### 7.2 The ceremony

```bash
infra/rpi5-k3s/scripts/02-vault-ceremony.sh
```

It runs `vault operator init -key-shares=5 -key-threshold=3` **attached to your
terminal** — no pipe, no tee, no capture — and writes neither a share nor the root
token to disk. Five shares and one root token appear once. Before you run it, have
five places ready that do not fail together; three of five must cooperate to
unseal, and that is defeated by putting all five in one password manager. Keep no
share with the root token. Your terminal's scroll-back is a file: clear it.

The script then offers to unseal three times, and refuses to assume an answer on
a non-interactive shell.

### 7.3 Policy, token, and revoking root

Stage 30 does the rest. Its policy is `file()` on
`docker/vault/axiam-policy.hcl` — the same file `scripts/vault-policy.sh` writes
and `just prod-up` uses, so the Kubernetes deployment and the documented Compose
ceremony cannot drift from each other or from what the server needs.

The shape is "read-only on the deployment secrets, plus writes confined to the
CA-key prefix", and both halves are load-bearing. A token with only the first
half boots fine, serves every request, and then answers the first CA generation
with a 403 on write — because CA key custody **inherits**
`AXIAM__AUTH__VAULT_ADDR` and `_TOKEN` when no `AXIAM__PKI__VAULT_*` pair is set,
which is the single-Vault arrangement the overlay configures.

Seeding goes through `scripts/vault-seed.sh` and nothing else. It mints only what
is missing, and the guarantee rests on a read it refuses to guess at: it waits for
an **active** node (200 on `sys/health`, not a 429 standby or a 503 sealed), hands
its payload builder the read's HTTP *status* rather than the body alone, and
writes with KV v2's `cas`. It also mints the Ed25519 JWT keypair itself, with
openssl, without the key touching disk — which is why nothing in the OpenTofu tree
generates one.

**Then revoke the root token.** `run.sh` prints the command. It has done its job
and it is the one credential that can undo everything above.

### 7.4 Prove the scope is what you think it is

Writing a policy and *attaching* it are two steps, and nothing inside AXIAM can
tell a scoped token from a root one — both read the secret successfully.

```bash
VAULT_TOKEN="$(kubectl -n axiam get secret axiam-vault-token \
  -o jsonpath='{.data.AXIAM__AUTH__VAULT_TOKEN}' | base64 -d)" \
  infra/rpi5-k3s/scripts/05-verify.sh
```

It must say `ok`, not `OVER-SCOPED`. `run.sh` runs the same check at the end of a
stage-30 apply, using the repository's own `scripts/vault-status.py` — that tool
is pure stdin/JSON and assumes nothing about Docker, so it is reused rather than
forked; only `just vault-status`'s Compose plumbing had to be replaced.

Expect the **seal** section to say `SHAMIR` unless you did §7.1. It is telling the
truth.

### 7.5 Back it up

```bash
read -rs VAULT_TOKEN && export VAULT_TOKEN
infra/rpi5-k3s/scripts/04-backup.sh --rsync you@elsewhere:axiam-backups/
unset VAULT_TOKEN
```

Raft snapshot + a SurrealDB export + the OpenTofu state, in one 0600 archive.
The snapshot needs a token with `read` on `sys/storage/raft/snapshot`, which the
`axiam` policy deliberately does not grant — issue a short-lived one and revoke
it.

It does **not** back up your unseal shares. They are not on this machine, which is
the point of the ceremony. **Copy the archive off the Pi**: a backup on the disk
you are backing up protects you from the failures you were not worried about.

---

## 8. Reboots

There is no `axiam-stack.service` to write. `k3s.service` is enabled by the
installer, and every pod is restarted by its controller.

With auto-unseal, the stack comes back on its own. Without it, the symptom is
specific and worth recognising on sight: **`axiam-server` crash-looping while
`vault-0` is Running and Ready.** Vault answers its readiness probe while sealed;
a sealed Vault is a condition for a human to fix, not something a restart
improves, which is why the manifest has no liveness probe on `/sys/health`.

```bash
kubectl -n axiam get pods
infra/rpi5-k3s/scripts/02-vault-ceremony.sh    # unseals; it will not re-initialise
```

Health probes, which are not routed publicly (§2):

```bash
kubectl -n axiam port-forward svc/axiam-server 18090:8090 &
curl -fsS --cacert <(kubectl -n axiam get secret axiam-server-tls \
       -o jsonpath='{.data.ca\.crt}' | base64 -d) \
     --resolve axiam-server.axiam.svc:18090:127.0.0.1 \
     https://axiam-server.axiam.svc:18090/health/jobs | python3 -m json.tool
```

---

## 9. First-run bootstrap

`infra/rpi5-k3s/scripts/03-axiam-bootstrap.sh` does it. The semantics — one-shot,
fail-closed, the organization-scope tenant, which tenant the provider configs land
in — are unchanged and are in
**[Pi guide §9](../../claude_dev/rpi5-prod-google-federation-guide.md#9-first-run-bootstrap)**.

One Kubernetes-specific note. The setup token is minted once and logged once, and
Kubernetes keeps only the current container's output. If the pod has restarted,
the line is gone — `kubectl -n axiam logs deploy/axiam-server --previous` may
still have it, and otherwise the `AXIAM_BOOTSTRAP_ADMIN_EMAIL` gate is your way
in. The script tries both and says which it used.

---

## 10. The five identity providers

Unchanged; none of it is about the container runtime.
**[Pi guide §10](../../claude_dev/rpi5-prod-google-federation-guide.md#10-the-five-providers).**
Redirect URI `https://axiam-iam.duckdns.org/auth/sso/callback` for every provider
but Apple, which uses `…/api/v1/auth/federation/oidc/callback/form`.

`infra/rpi5-k3s/scripts/providers.example.yml` is a template for feeding them to
`03-axiam-bootstrap.sh --federation`. **Copy it, never edit it in place** — the
copy holds real client secrets, and `providers.yml` is gitignored. Adding them in
the admin UI instead is better: a secret typed into a browser form was never in a
file, a shell history or a backup.

---

## 11. The admin UI, and signing in

Unchanged.
**[Pi guide §11](../../claude_dev/rpi5-prod-google-federation-guide.md#11-configure-them-in-the-admin-ui-and-sign-in).**

---

## 12. Verify

`infra/rpi5-k3s/scripts/05-verify.sh`, eleven layered sections. Layered on
purpose: when something is wrong, knowing *which* hop failed saves an hour.
Nothing in it uses `-k` or any verification-skip option — a TLS failure there is a
finding.

Two of its checks deserve naming, because they are the ones that prove a control
is actually applying rather than merely configured:

- **default-deny is denying.** It execs into the frontend pod and tries to open
  `surrealdb:8000`. That must fail. A NetworkPolicy with no enforcing CNI is a
  document, not a control.
- **`restricted` is admitting.** It asks the API server to dry-run a privileged
  pod. That must be refused. The namespace label says what should happen;
  admission is what does.

Then **[Pi guide §12](../../claude_dev/rpi5-prod-google-federation-guide.md#12-verify-what-axiam-created)**
for what AXIAM itself should have created after a federated sign-in.

---

## 13. IoT devices and mTLS

**A client certificate cannot reach the backend through the ingress.**
ingress-nginx terminates TLS, so a certificate a device presents is verified there
and never seen by rustls — and AXIAM's device identity comes from the
*rustls-verified* peer certificate. The `X-Client-Certificate` header fallback is
off by default (`AXIAM__AUTH__TRUST_FORWARDED_CLIENT_CERT: "false"` in the base
ConfigMap) and must stay off: a certificate is public data, so a header carrying
one proves nothing about who sent it.

On Compose the answer is a second hostname the proxy does not touch (Pi guide
§13). On Kubernetes the same idea has two shapes, and **this deployment builds
neither** — it describes them so you can decide:

- **A TCP passthrough.** ingress-nginx can proxy raw TCP with its `tcp-services`
  ConfigMap, on a port that is not 443, forwarding to `axiam-server:8090` without
  terminating anything. rustls then does the handshake and sees the client
  certificate. Costs a second forwarded port at the router.
- **A `hostPort` on the server pod.** Simpler and blunter: the container binds a
  port on the node directly. It puts a listener outside the ingress and outside
  everything the NetworkPolicies describe, so be deliberate.

Either way, `AXIAM__SERVER__TLS__CLIENT_AUTH` becomes `optional` — `optional` so
the one listener serves both the ingress (which presents no certificate) and
devices (which do) — and you flag the organization CA as an mTLS trust anchor in
the admin UI.

**One hazard to close.** On a direct route there is no proxy, so a client can send
its own `X-Forwarded-For`, and with `TRUSTED_HOPS=0` and a single-entry header the
extractor selects the client's own value — a fresh rate-limit bucket per request.
Strip the header at your firewall for that port, or do not publish the route.

---

## 14. Optional: gRPC on the public internet

Off by default (`grpc_public = false`). Read
**[Pi guide §14](../../claude_dev/rpi5-prod-google-federation-guide.md#14-optional-grpc-on-the-public-internet)**
first — it explains what is on the wire, what the rate-limit families are, and why
publishing this is a defensible choice and still a choice.

Here it is one variable:

```hcl
grpc_public = true
```

which does three things that must happen together: adds
`overlay/ingress-grpc.yml` to the render, sets `AXIAM__GRPC_TLS_CERT_PATH` and
`AXIAM__GRPC_TLS_KEY_PATH` to **the same leaf the REST listener serves**, and sets
`AXIAM__GRPC__STRICT_REVOCATION=true`.

- **The certificate paths are flat names** — `AXIAM__GRPC_TLS_CERT_PATH`, not
  `AXIAM__GRPC__TLS__CERT_PATH`. The wrong spelling is silently ignored and the
  listener comes up in cleartext. Both or neither: the server panics at startup if
  either names a file it cannot read, which is deliberate — a typo is a failed
  boot, never a quiet cleartext listener.
- **One certificate, both listeners, one reloader.** There is no second
  certificate and there must not be.
- **`STRICT_REVOCATION`** because by default the gRPC data plane validates a
  token's signature and expiry and stops there, so a session revoked by logout or
  admin sign-out keeps passing until the access token expires — up to 15 minutes.
  On a listener the internet can reach, take REST's semantics. On one replica the
  session-validation cache makes a logout take effect immediately.

**Never publish gRPC as a NodePort at 50051.** Nothing then writes
`X-Forwarded-For`, so a client that sends its own is keyed on a value it chose,
and one it varies per call is a fresh bucket per call. No `TRUSTED_HOPS` value
closes that: for any *n*, a client sending *n+1* entries selects the leftmost one
it wrote. The header is trustworthy only because a proxy you run overwrites it.

The Ingress publishes **three** services by path prefix —
`AuthorizationService`, `UserInfoService`, `TokenService`. That allowlist is the
security control. Add `UserService` only if something remote needs it
(`ValidateCredentials` is a password check), and never publish a bare
`/axiam.v1.` prefix.

---

## 15. Migrating from the Compose Pi

**Vault:** a Raft snapshot restores cleanly into the new Vault. Take one on the
Compose stack (`vault operator raft snapshot save`), copy it over, and restore it
into the freshly initialised k3s Vault with `vault operator raft snapshot restore`.
The seal must match: a snapshot taken under Shamir restores into a Shamir Vault.
Restoring the snapshot is what preserves `opaque_setup_key`, and therefore what
saves every user from a password reset.

**SurrealDB:** `surreal export` on the Compose stack and `surreal import` into the
new one. **Check the flags against the image you are running before you rely on
this** — they have changed between majors, and `04-backup.sh` says the same thing
where it uses them. If the export does not work on your version, the honest path
is a fresh bootstrap and users re-enrol; do not plan a migration around a tool you
have not run.

**Everything else** — DuckDNS, the router, the five IdP registrations, the
redirect URIs — carries over untouched, because none of it is about the container
runtime. Your public hostname does not change, so neither do your passkeys.

Do it in this order: snapshot and export first, on the running Compose stack, and
verify you can read both files. Then stop the Compose stack — you cannot have both
listening on 443. Then §5.

---

## 16. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `kubectl` says the memory cgroup is unavailable; k3s restart-loops | `cgroup_memory=1 cgroup_enable=memory` is not on the running kernel's command line | `00-host-prepare.sh`, then **reboot**. Confirm with `grep -w memory /proc/cgroups` — the `enabled` column must be 1 |
| kubelet refuses to start, mentioning swap | `dphys-swapfile` | `00-host-prepare.sh` disables it permanently; `swapoff -a` alone comes back on the next boot |
| `vault-0` stuck in `ContainerCreating` | the `vault-tls` Secret does not exist | `kubectl -n axiam get certificate vault-tls` — it should be `Ready=True`. If cert-manager's CRDs are missing, stage 10 was not applied |
| `vault-0` `CreateContainerError`, or the pod is rejected at admission | the Vault StatefulSet predates K8S-F2 | It must have `disable_mlock = true`, no `IPC_LOCK`, and a `seccompProfile`. `kubectl -n axiam describe statefulset vault` shows the admission message |
| `kubectl apply` refuses to update the Vault StatefulSet, naming `spec.selector` | the selector changed in K8S-F11 and a selector is immutable | `kubectl -n axiam delete statefulset vault --cascade=orphan && kubectl apply -k k8s/`. The PVC and the running pod both survive |
| `axiam-server` in `CreateContainerConfigError`, `secret "axiam-vault-token" not found` | you are between stage 20 and stage 30 | Correct and expected. Run the ceremony and stage 30 |
| `axiam-server` crash-looping, `vault-0` Running and Ready | Vault is **sealed**. It answers its readiness probe while sealed, on purpose | Unseal (§7.2). Then do §7.1, which is why this happened |
| Server starts, then dies on its first secret fetch, on a healthy Vault | the server→Vault NetworkPolicy path (K8S-F1) | Both halves are needed: `server-egress` on 8200 **and** `allow-ingress-to-vault`. `kubectl -n axiam get netpol` |
| Server never becomes Ready; probes fail; the logs look fine | the probes are HTTP against a TLS listener | Both probes need `scheme: HTTPS` (K8S-F5) |
| `failed to open TLS key file` at startup | the 0440 mount and `fsGroup: 65532` disagree | They change together or not at all. `kubectl -n axiam get deploy axiam-server -o yaml` and compare the `defaultMode` with the pod `securityContext` |
| The ingress answers 502 on `/api` while the SPA works | the upstream TLS leg | `kubectl -n ingress-nginx logs ds/ingress-nginx-controller --tail=50`. Usually `proxy-ssl-secret` naming a Secret that is not there, or `proxy-ssl-name` not matching a SAN on `axiam-server-tls` |
| No certificate ever issues | HTTP-01 cannot reach you | Test port 80 from **outside** your LAN. Then `kubectl -n axiam get challenge` — it names the exact failure. If your ISP blocks 80, §4.1 |
| Let's Encrypt starts refusing orders | production rate limits | You did not use `letsencrypt-staging` first. Wait out the week; there is no appeal |
| `/health` returns the SPA HTML | working as designed (§2) | Probe through a port-forward (§8) |
| Everyone rate-limited at once | `TRUSTED_HOPS` wrong for the topology, or the controller is not on hostNetwork | §6.2. Do not raise `TRUSTED_HOPS` to compensate for a SNAT hop; remove the hop |
| A second device is throttled the instant the first is | same | §6.2, and it is the check to run before you call this done |
| Login answers 500 — `Cryptography error: AES-GCM decrypt: aead::Error` | a key in Vault no longer matches what the datastore was sealed with | KV v2 keeps ten versions. `docs/deployment/vault.md` §8.1 has the `vault kv metadata get` / `vault kv patch` recovery, which needs no password resets |
| `federation encryption key not configured` | `federation_encryption_key` missing from Vault, or the server started before seeding | Re-run stage 30, then `kubectl -n axiam rollout restart deploy/axiam-server` |
| Passkey enrolment fails with 401 | `AXIAM_WEBAUTHN_RP_ORIGIN` does not match the address bar | `overlay/configmap-env.yml`, then restart the deployment |
| gRPC returns HTML, or a protocol error naming `text/html` | the path is not in the §14 allowlist | Check the service name character for character |
| `gRPC TLS is DISABLED` in the log although the variables are set | the name. It is `AXIAM__GRPC_TLS_CERT_PATH`, not `AXIAM__GRPC__TLS__CERT_PATH` | §14. Both variables, or neither |
| `tofu init` fails on a provider checksum | a `.terraform.lock.hcl` that does not match what the registry serves | This tree ships none, deliberately. Delete any you did not generate yourself and re-run `init` |
| Stage 30 cannot reach Vault | the port-forward, or the CA | `run.sh` opens the forward and extracts `ca.crt` from the `vault-tls` Secret. Check `kubectl -n axiam get secret vault-tls` |
| The whole site 502s about a year after install | the Vault or RabbitMQ leaf renewed and neither process reloads TLS files | §4.3. `kubectl -n axiam rollout restart statefulset/vault statefulset/rabbitmq`. Put it in your calendar next time |

---

## 17. Before you call this production

### The invariants, and the file that enforces each

| # | Invariant | Enforced by |
|---|---|---|
| 1 | Exactly one reverse proxy between client and server, hence `TRUSTED_HOPS=0` | `overlay/configmap-env.yml`; `tofu/10-platform/main.tf` (`hostNetwork: true`, `use-forwarded-headers: "false"`, `service.enabled: false`); `scripts/01-install-k3s.sh` (`--disable servicelb`) |
| 2 | The backend terminates its own TLS 1.3 | `k8s/server/configmap.yml` (`AXIAM__SERVER__TLS__ENABLED: "true"`), `k8s/server/deployment.yml` (the `server-tls` volume) |
| 3 | `/health`, `/ready`, `/health/jobs` are not routed publicly | `k8s/ingress.yml` — only `/api`, `/oauth2`, `/.well-known` and `/` |
| 4 | gRPC is off the internet by default, and goes through the ingress if published | `k8s/server/service.yml` (ClusterIP); `overlay/ingress-grpc.yml` is not in `kustomization.yml` |
| 5 | The server holds a read-only, scoped Vault token, never root | `tofu/30-vault-config/main.tf`, `file()` on `docker/vault/axiam-policy.hcl`; checked by `05-verify.sh` §10 |
| 6 | `opaque_setup_key` is never regenerated | `scripts/vault-seed.sh` and nothing else; `tofu/30-vault-config/main.tf` calls it rather than using `vault_kv_secret_v2` |
| 7 | SurrealDB runs `surrealkv:`, never `memory` | `k8s/surrealdb/statefulset.yml`; the overlay touches only the image tag |
| 8 | AMQP is `amqps://` on 5671 only | `k8s/rabbitmq/statefulset.yml`; the AMQP URL in `tofu/20-axiam/credentials.tf` |
| 9 | A released tag, real image names, `linux/arm64` | `overlay/kustomization.yml` `images:` |
| 10 | PSA `restricted` enforced, NetworkPolicy default-deny both ways | `k8s/namespace.yml`, `k8s/network-policy/`; both probed by `05-verify.sh` §8–§9 |
| 11 | The six mandatory runtime settings are set | `overlay/configmap-env.yml` |
| 12 | Double underscore, except where the code reads a flat name | `k8s/server/configmap.yml`'s header and §5.1 |

### The checklist

- **Read the table at the top of this document.** `tofu validate` has never run
  against this HCL, nothing here has been applied to a cluster, and the scripts'
  happy paths have never executed. Plan every stage before you apply it.
- **Auto-unseal (§7.1).** If you skipped it you do not have a production
  deployment — you have one that needs a human awake after every power cut. This
  is the single most important item on this list.
- **The root token is revoked**, and `05-verify.sh` §10 says `ok`, not
  `OVER-SCOPED`.
- **Unseal shares are off the Pi**, in three places that do not fail together, and
  not with the root token.
- **The OpenTofu state is encrypted and backed up off the device**, and so is a
  Vault Raft snapshot (§7.5). Losing the Vault loses the OPAQUE setup key, which
  means a password reset for every user in every tenant.
- **Only 80 and 443 are forwarded.** 6443 is the Kubernetes API server; it is on
  the host network and it is not a thing to publish.
- **The `TRUSTED_HOPS` two-address check (§6.2) has actually been run**, from two
  networks, and gave separate buckets.
- **A certificate has renewed at least once**, or you have confirmed
  `AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS` is not `0` and seen
  `TLS leaf certificate reloaded` in the logs.
- **You know when the Vault and RabbitMQ leaves expire** (§4.3), and it is in a
  calendar rather than in your memory.
- **You are running a released tag**, not `main`.
- **Client secrets rotated** if any was ever pasted into a shell with history, and
  `providers.yml` is not in git.
- Consider putting the admin UI behind a VPN or Tailscale and publishing only what
  a login page needs. The public API surface is small.

---

## Appendix: decisions revised on evidence

The plan this deployment was built from
([`claude_dev/rpi5-k3s-opentofu-plan.md`](../../claude_dev/rpi5-k3s-opentofu-plan.md))
made its decisions by reading the tree. Four of them turned out to rest on an
assumption that does not hold, and were changed rather than followed.

| Decision | What the plan assumed | What is true | Consequence |
|---|---|---|---|
| **D2** — `use-forwarded-headers: "false"` because "it appends the real peer to the right" | ingress-nginx appends to `X-Forwarded-For`, like Caddy and like `proxy_add_x_forwarded_for` | At chart 4.15.1 `nginx.tmpl` emits `proxy_set_header X-Forwarded-For $remote_addr` unless **both** `use-forwarded-headers` and `compute-full-forwarded-for` are true. It **replaces** | The value of `TRUSTED_HOPS` is unchanged (`0`) but the derivation is not, and the property is stronger — a forged header is discarded, not out-voted. §6.2 |
| **D5** — stage 20 generates the JWT keypair with `tls_private_key` and passes the PEMs to the seeder | the seeder needs to be given a keypair | `vault_seed_payload.py` mints an Ed25519 pair itself with openssl, without the key touching disk, whenever neither supplied nor present | No `tls_private_key` anywhere. The JWT signing key exists only in Vault, never in the OpenTofu state |
| **F10** — the overlay sets `AXIAM__PKI__VAULT_ADDR`, `_TOKEN`, `_CA_CERT_PATH` | CA key custody needs its own Vault configuration | `vault_endpoint_from` in `crates/axiam-pki/src/ca_key_store.rs` **inherits** the `AXIAM__AUTH__VAULT_*` trio when the PKI pair is absent, and `custodians_from` then defaults custody to `vault`. A half-filled PKI pair is refused at startup | The overlay sets only `AXIAM__PKI__CA_KEY_STORE: "vault"`, which is redundant as a value but converts a silent `database` fallback into a startup failure |
| **F2** — `restricted` requires `runAsGroup` | — | It does not. `restricted` requires `runAsNonRoot`, `allowPrivilegeEscalation: false`, `drop: [ALL]` with at most `NET_BIND_SERVICE` added, and a `seccompProfile` | `runAsGroup: 1000` is set on the Vault pod anyway, as hardening rather than as an admission requirement, and the commit says which |

And one finding the plan did not have, which had to be fixed before K8S-F1 could
be:

**K8S-F11.** `k8s/kustomization.yml` applies `commonLabels: {app: axiam}`, and
kustomize rewrites Service selectors and workload `spec.selector` along with the
labels. The Vault Service and StatefulSet selected on the bare `app: vault`,
which did **not** survive the render — it became `app: axiam`.

The rendered Vault Service therefore selected **every pod in the namespace**, so
`https://vault.axiam.svc.cluster.local:8200` load-balanced across axiam-server,
axiam-frontend, surrealdb and rabbitmq, and the server's first secret fetch
reached Vault only when round-robin happened to pick it. The StatefulSet's
selector overlapped every other workload for the same reason. It was also why no
NetworkPolicy could name Vault, which is what blocked K8S-F1.

Fixed by giving Vault the `component: vault` label every other component in the
tree already had — a shape kustomize cannot collapse, because it overwrites
`app` with the value it already has and leaves `component` alone. Note the
upgrade step in §16: `spec.selector` is immutable.

Two smaller surprises, recorded because the next person will hit them:

- **The overlay is `infra/rpi5-k3s/overlay/`, not `k8s/overlays/rpi5-k3s/`.**
  Kustomize refuses to build an overlay nested inside its own base root
  (`cycle detected: candidate root k8s contains visited root
  k8s/overlays/rpi5-k3s`), and `k8s/` itself is the base — splitting it into
  `k8s/base/` would change the `kubectl apply -k k8s/` command
  `docs/deployment/README.md` documents.
- **kustomize v5.4.2 segfaults** on a multi-document strategic-merge patch listed
  under `patches:`. The three `$patch: delete` documents that remove the blank
  credential Secrets are therefore three files.
