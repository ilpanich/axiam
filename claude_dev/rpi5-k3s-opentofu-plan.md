# AXIAM on a Raspberry Pi 5 with k3s and OpenTofu — feasibility answer and build plan

> **EXECUTED 2026-09-16, at `1.0.0-beta15`.** All six waves of §6 were worked in
> order on `claude/rpi5-k3s-opentofu-deploy-ge4ff4`, in eleven commits. Everything
> §5 lists is delivered: five base fixes in `k8s/`, the certificate examples in
> `k8s/certs/`, the Pi overlay, six host scripts, three OpenTofu stages with the
> `run.sh` wrapper, and the operator guide at `docs/deployment/rpi5-k3s.md`.
> Nothing in §5's "not deliverables" was touched — no Rust, no `Cargo.*`, no
> website, no SDK contract, no Compose path.
>
> **Every §4 finding reproduced**, and one more was found that the plan did not
> have. **K8S-F11:** `commonLabels: {app: axiam}` in `k8s/kustomization.yml`
> collapsed the Vault `Service` and `StatefulSet` selectors from `app: vault` to
> `app: axiam`, so the rendered Vault Service selected *every pod in the
> namespace* and `https://vault.axiam.svc.cluster.local:8200` load-balanced
> across the server, the frontend, SurrealDB and RabbitMQ. It also left no label
> for a NetworkPolicy to name, which is what blocked F1. Fixed first, as its
> prerequisite.
>
> **Four decisions were revised on evidence**, each recorded in the guide's
> §Appendix decision table. **D2's mechanism was wrong**: ingress-nginx does not
> append to `X-Forwarded-For` — at chart 4.15.1 `nginx.tmpl` emits
> `proxy_set_header X-Forwarded-For $remote_addr` unless both
> `use-forwarded-headers` and `compute-full-forwarded-for` are true, so it
> *replaces*. `TRUSTED_HOPS` stays `0` and the property is stronger, but the Pi
> guide §6.3's derivation does not carry over and §17 there now says so.
> **D5 no longer generates the JWT keypair**: `vault_seed_payload.py` mints an
> Ed25519 pair itself with openssl, without the key touching disk, so a
> `tls_private_key` resource would have put a signing key in the state for no
> benefit. **F10 sets no `AXIAM__PKI__VAULT_*` variables**: `vault_endpoint_from`
> inherits the `AXIAM__AUTH__VAULT_*` trio and defaults custody to `vault`, and a
> half-filled PKI pair is a startup failure — only `AXIAM__PKI__CA_KEY_STORE` is
> set, to convert a silent `database` fallback into a loud one. **F2's
> `runAsGroup` is not a `restricted` requirement**; it is set anyway, as
> hardening, and the commit says which.
>
> **Two path changes**, both forced by kustomize and both recorded where they
> are. The overlay is `infra/rpi5-k3s/overlay/`, not `k8s/overlays/rpi5-k3s/`:
> kustomize refuses to build an overlay nested inside its own base root, and
> `k8s/` *is* the base, so the alternative was splitting it into `k8s/base/` and
> invalidating the `kubectl apply -k k8s/` command `docs/deployment/README.md`
> documents. And the three `$patch: delete` documents that hand the credential
> Secrets to OpenTofu are three files, because kustomize v5.4.2 segfaults on a
> multi-document strategic-merge patch listed under `patches:`.
>
> **§7 was applied literally, and the honest half of it matters more than the
> other.** Executed: both kustomize renders, `kubeconform -strict` (29/29 base,
> 25/25 overlay, 9/9 cert-manager CRs against the upstream CRD schemas), a static
> re-implementation of the Pod Security `restricted` field list that reproduces
> the pre-fix F2 failure before confirming 5/5 after it, the rendered
> overlay-vs-base diff reviewed line by line, `shellcheck -S warning` and
> `bash -n` on every script, `tofu fmt -check -recursive`, `check-doc-links.sh`,
> a Trivy config scan whose only HIGH is pre-existing (verified by scanning the
> tree at `d20293a`), and — beyond what §7 asked — every pinned version fetched
> from its real release and every pinned image's manifest list resolved to
> confirm `linux/arm64`.
>
> **Not executed, and named at the top of the operator guide as well as here:**
> `tofu init`, `tofu validate` and `tofu plan` never ran, because
> `registry.opentofu.org` *and* `registry.terraform.io` both answer 403 through
> the authoring environment's proxy and no provider could be downloaded. The HCL
> has therefore been formatted but never semantically checked, and no
> `.terraform.lock.hcl` is shipped — a hand-written one would fail `init` on a
> checksum mismatch, which is worse than none. `helm template` could not run
> either (`get.helm.sh` and the helm GitHub releases are both blocked), so stage
> 10's chart values have never been rendered. Nothing was applied to a cluster;
> the scripts' guards were exercised but their happy paths were not; and the
> two-address `TRUSTED_HOPS` check needs two public networks. **Plan every stage
> on the Pi before applying it.**
>
> Two code observations were recorded rather than fixed, per §8's scope rule:
> the base Deployment's inline `AXIAM__AUTH__SECRET_PROVIDER: "file"` silently
> overrides the ConfigMap's documented `vault` (noted in the F1 commit and the
> overlay), and Trivy's inline `#trivy:ignore:` comments do not apply to
> Kubernetes YAML in 0.70.0 — which is why the Vault-provider patch is JSON 6902
> rather than a suppression.

**Status:** ~~planning document~~ **EXECUTED**, written 2026-09-16 against
`1.0.0-beta15` (`main` at `7505ae5`), executed the same day. §9 is the prompt
that started the executing session.
**Audience:** first the maintainer, who asked two questions and gets them
answered in §0; then the executing session, which must read every section.
**Companion documents:**
[`rpi5-prod-google-federation-guide.md`](rpi5-prod-google-federation-guide.md)
(the Compose-based Pi runbook this plan re-targets — "the Pi guide" below) and
[`public-backend-tls-design.md`](public-backend-tls-design.md) (why the
topology is shaped as it is; every invariant in §1 comes from there).

Everything below is derived from what is in this repository at this commit.
Where the code or the shipped manifests and a plausible expectation disagree,
the code wins and the disagreement is called out — several such disagreements
are listed in §4, and they are the reason this is a plan and not a paragraph.

---

## 0. The two questions, answered

### 0.1 Can the Pi-guide setup run on Kubernetes on a Raspberry Pi 5? Yes — with k3s, not minikube

Kubernetes on a Pi 5 is routine today, and the repository is already closer to
it than to Compose: `docker-compose.prod.yml` says in its own header that it is
*not* the production path and that `k8s/` is, the Pi guide repeats that in
§17, and `public-backend-tls-design.md` §1.3 explicitly reshaped the Compose
topology to match the Kubernetes one. Moving the Pi to Kubernetes is moving it
onto the path the repository already calls supported.

The distribution matters more than the fact of it:

| Option | Fit for one Pi that is reachable from the internet |
| --- | --- |
| **k3s** | **Recommended.** One static arm64 binary, systemd unit, ~500 MB idle. Real kubelet on the host network, so a public listener on 80/443 is an ordinary Pod, not a tunnel. Ships CoreDNS, a NetworkPolicy controller, `local-path` storage and metrics-server. Traefik and ServiceLB are bundled but can be disabled at install time, which this plan does (§3 D2). |
| minikube | **Not for this.** It is a development tool: the cluster runs inside a container or VM on the Pi, public ingress needs `minikube tunnel` or port mapping through the driver, it does not come back cleanly after a power cut, and nothing in it is designed to face the internet. It would work for a demo and would be the wrong thing to call production. |
| MicroK8s | Works on Ubuntu Server arm64 via snap, noticeably heavier than k3s, and its `ingress` and `cert-manager` add-ons pin versions you do not choose. Acceptable if the operator already prefers it; not the default here. |
| kubeadm | The full upstream install. Correct, heavier, and every component k3s bundles becomes an operator decision. Not worth it for one node. |

**Resource fit.** The Pi guide already says 8 GB recommended, 4 GB tight, for
Compose. With k3s the control plane itself takes roughly 500–700 MB, ingress-nginx
~150 MB, cert-manager ~120 MB across its three pods, Vault ~150 MB, so the same
verdict holds with less margin: **8 GB required, NVMe or SSD strongly
recommended** (SurrealDB's `surrealkv` on an SD card is described in the Pi
guide as "miserable", and now `local-path` PVCs for RabbitMQ and Vault share
that disk). The shipped `replicas: 2` and the HPA (§4 F6) must come down to one
replica each; two copies of everything on one node buys nothing and costs ~1 GB.

**What changes for the operator, in one table** (the k3s counterpart of the Pi
guide's §0):

| Pi guide (Compose) | This plan (k3s) | Why |
| --- | --- | --- |
| Caddy on the host, systemd | **ingress-nginx** as a hostNetwork DaemonSet in the cluster | The shipped `k8s/ingress.yml` and every NetworkPolicy already assume ingress-nginx; keeping it means the manifests work unchanged. §3 D2 |
| certbot on the host owns ACME; a deploy hook copies the leaf | **cert-manager** owns ACME; the leaf lives in a `Secret` both the Ingress and the server pod read | Same principle — one ACME client, two consumers — expressed the Kubernetes way. Renewal needs no hook: the kubelet refreshes the mounted files and the server's hourly poll (`server.tls.reload_interval_secs`) picks them up. §3 D3 |
| Backend serves the **public** Let's Encrypt leaf | Backend serves a leaf from an **in-cluster private CA** (cert-manager), which the ingress verifies | `public-backend-tls-design.md` §3.1 says this is exactly what Kubernetes would do. ingress-nginx cannot verify an upstream against the public roots without a client keypair anyway. §3 D3 |
| `just prod-up` mints credentials and runs a laptop Vault ceremony | **OpenTofu** mints credentials into `Secret`s; the Vault ceremony is a **human** script (5-of-3), then OpenTofu configures mount, policy and the server token | §0.2 and §3 D4 |
| `~/axiam-up.sh` + `axiam-stack.service` | Nothing: k3s is a systemd unit and pods restart themselves | With auto-unseal (Pi guide §7.1) the stack comes back on its own; without it a human unseals, exactly as before |
| `TRUSTED_HOPS=0` because Caddy is the one proxy | **Still `0`**: ingress-nginx is the one proxy, and hostNetwork mode makes the real client the socket peer | Load-bearing; verified the same way (Pi guide §6.3). §3 D2 |
| gRPC optional via a Caddy `handle` on 443 | gRPC optional via a second `Ingress` with `backend-protocol: GRPCS`, same allowlist of three services | Pi guide §14 unchanged in substance |
| Everything else — DuckDNS, router, the five IdPs, `/auth/sso/callback`, bootstrap, federation configs, WebAuthn and issuer settings | **Unchanged** | None of it is about the container runtime |

### 0.2 Can the provisioning be done with Terraform or OpenTofu? Yes for the platform, the manifests, the Vault configuration and the secrets; four things must stay outside it

**Yes:**

- **Cluster add-ons** — ingress-nginx, cert-manager and its CRDs, the
  `ClusterIssuer`s, metrics-server if not bundled: the `helm` provider does
  this cleanly and idempotently.
- **The AXIAM manifests** — the shipped `k8s/` base plus a Pi overlay, applied
  through the `kbst/kustomization` provider (a `kustomization_overlay` data
  source rendered into `kustomization_resource`s, one state object per
  manifest, real diffs on `plan`). The alternative, `kubernetes_manifest` per
  object, is the same thing with more boilerplate and a CRD-ordering problem.
- **Credentials and key material** — SurrealDB and RabbitMQ passwords via
  `random_password`, the AMQP URL assembled from them, the Ed25519 JWT keypair
  via `tls_private_key`, all written into the `Secret`s the base manifests
  leave blank. Two hard rules follow from the Pi guide: these are honoured
  **only on the first boot of an empty volume**, so every one carries
  `lifecycle { ignore_changes = all; prevent_destroy = true }`; and they are
  in the state file, so **the state is a secret** (§3 D5).
- **Vault configuration after the ceremony** — the `vault` provider enables
  the KV v2 mount, writes the policy from `docker/vault/axiam-policy.hcl`
  (the same file the Compose path uses, read with `file()` — one source of
  truth), issues the periodic `axiam` token and writes it into the server
  `Secret`. **Not the secrets themselves:** `vault_kv_secret_v2` would put the
  OPAQUE setup key in the state file. Seeding runs the repository's own
  `scripts/vault-seed.sh`, which is idempotent, CAS-guarded and refuses to
  write into a Vault it cannot read — properties a provider resource does not
  have and which the Pi guide §16 shows were earned the hard way.
- **Microsoft Entra**, if used — `azuread_application` and
  `azuread_application_password` fully describe the app registration of the
  Pi guide §10.5.

**No, and the plan says so rather than pretending:**

1. **Installing k3s itself.** The provider that would apply everything needs a
   cluster to talk to. A shell script installs k3s; OpenTofu starts after
   that. (A `terraform_data` with a local provisioner could wrap the script,
   but that hides a one-time host mutation behind a tool whose value is
   convergence, and it converges on nothing.)
2. **The Vault init/unseal ceremony.** There is no `vault_init` resource, and
   there must not be one: `vault operator init -key-shares=5 -key-threshold=3`
   prints five shares **once**, to be handed to five places that do not fail
   together (Pi guide §7.2). A tool that stores its inputs is the wrong tool.
   The Compose path's `prod-up` does this with one share written next to the
   data, and the Pi guide spends all of §7 undoing it; this plan does not
   repeat it.
3. **Registering the identity providers.** Google has no Terraform resource
   for OAuth clients under the Google Auth Platform (`google_iap_client` is
   IAP-only); GitHub OAuth Apps, Facebook apps and Apple Services IDs have no
   provider at all. Those remain the click-through steps of Pi guide §10, and
   the guide already describes them precisely. Only Entra is automatable.
4. **AXIAM's own first-run configuration** — `POST /api/v1/admin/bootstrap`
   and `POST /api/v1/federation-configs`. There is no AXIAM provider; a
   generic REST provider could do it, but bootstrap is one-shot and fail-closed
   (`bootstrap_lock:global`, setup token read from the first-boot log), which
   is the opposite of a resource that converges. A small script that reads the
   setup token from the pod log and posts the two requests is honest about
   what it is, and the plan ships that.

**OpenTofu or Terraform?** Write for both. OpenTofu is the default binary the
scripts install (arm64 builds exist for both; the licence question is the
operator's, not this plan's). The one OpenTofu-only feature worth using is
**state encryption**, because the state holds the datastore password and the
Vault token: put the `encryption` block in a file with the `.tofu` extension,
which OpenTofu reads and Terraform ignores by design, so the same tree
validates under both. No other OpenTofu-only syntax.

---

## 1. Invariants inherited from the repository — the executing session must not trade any of these away

Each of these is established in `public-backend-tls-design.md` or the Pi guide
and is either enforced by code or verified by an existing check. The k3s
variant has to preserve every one; where the shipped manifests do not (§4),
the fix is to make the manifests honour the invariant, never to relax it.

1. **Exactly one reverse proxy between the client and `axiam-server`**, hence
   `AXIAM__RATE_LIMIT__TRUSTED_HOPS=0` on both REST and gRPC (one variable,
   read by both; Pi guide §6.3, §14.2). Any topology that adds a hop — a
   `LoadBalancer` service that SNATs, a mesh sidecar — is a change to this
   number and must be derived, not assumed.
2. **The backend terminates its own TLS 1.3** (`AXIAM__SERVER__TLS__ENABLED=true`);
   no AXIAM credential crosses the pod network in cleartext. The Pi guide §6.1
   says why; a pod network on a single node is the Docker bridge with a
   different name.
3. **`/health`, `/ready`, `/health/jobs` are not routed publicly.** The
   shipped `k8s/ingress.yml` already routes only `/api`, `/oauth2`,
   `/.well-known` and `/`. Keep it that way; probe with `kubectl port-forward`
   or `kubectl exec`.
4. **gRPC is off the internet by default** (ClusterIP only; SEC-003) and, if
   published, goes **through the ingress on 443** with a per-service
   allowlist, never a `NodePort` at 50051 (Pi guide §14.2 explains why no
   `TRUSTED_HOPS` value can rescue a direct route).
5. **The server holds a read-only, scoped Vault token, never root**, and the
   root token is revoked after the ceremony (Pi guide §7.3–7.4). `just
   vault-status` must say `ok`, not `OVER-SCOPED`. The shipped policy
   (`docker/vault/axiam-policy.hcl`) additionally grants create/read/delete
   under `axiam/ca-keys/*`, which is what `AXIAM__PKI__CA_KEY_STORE=vault`
   needs; do not narrow it below that if CA custody is Vault.
6. **`opaque_setup_key` is never regenerated** after enrolment. Seeding goes
   through `scripts/vault-seed.sh` and nothing else.
7. **SurrealDB runs `surrealkv:`** (or `rocksdb:`), never `memory`
   (`docs/deployment/README.md`, the storage-engine MUST). The shipped
   StatefulSet already does; the overlay must not touch that argument.
8. **AMQP is `amqps://` on 5671 only**; the plaintext listener does not exist.
   The broker needs a certificate, so cert-manager is a **requirement** of the
   shipped manifests, not an addition of this plan (§4 F4).
9. **Deploy a released tag, not `main`** (Pi guide §1): image tags are the
   workspace version with the leading `v` stripped, `linux/arm64` under one
   manifest list, no moving tags. The overlay pins `1.0.0-beta15` (or whatever
   is current when the session runs; `git describe --tags` decides) and the
   real image names `ghcr.io/ilpanich/axiam/server` and `.../frontend`, not
   the `ghcr.io/OWNER/...` placeholder the base carries.
10. **Pod Security Admission `restricted` is enforced** on the `axiam`
    namespace (`k8s/namespace.yml`, SEC-053) and **NetworkPolicy is
    default-deny** both directions (D-11). Anything that does not admit under
    those constraints is fixed to admit, not exempted.
11. **The six settings the Pi guide §5.2 calls mandatory** —
    `AXIAM_WEBAUTHN_RP_ID`, `AXIAM_WEBAUTHN_RP_ORIGIN`,
    `AXIAM__AUTH__JWT_ISSUER`, `AXIAM__AUTH__OAUTH2_ISSUER_URL`,
    `AXIAM_BOOTSTRAP_ADMIN_EMAIL`, TLS on — are all still mandatory and none
    is in the shipped ConfigMap (§4 F7).
12. **Double underscore.** `AXIAM__DB__URL`, not `AXIAM_DB_URL`; the three
    exceptions (`AXIAM_BOOTSTRAP_ADMIN_EMAIL`, `AXIAM_HEALTHCHECK_URL`,
    `AXIAM__RATE_LIMIT__TRUSTED_HOPS`) and the two flat gRPC TLS names
    (`AXIAM__GRPC_TLS_CERT_PATH`, `AXIAM__GRPC_TLS_KEY_PATH`) are read with
    `std::env::var` and a misspelling is silence, not an error.

---

## 2. Target topology

```
                          Internet
                             │ 443 (and 80 for HTTP-01)
                             │ router forwards ONLY these two to the Pi
                             ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │ Raspberry Pi 5 · Raspberry Pi OS 64-bit · k3s (single node)      │
   │                                                                  │
   │  ns ingress-nginx                                                │
   │  ┌────────────────────────────────────────────────────────────┐  │
   │  │ ingress-nginx controller — DaemonSet, hostNetwork,         │  │
   │  │ listens on the node's 80/443. The ONLY public listener.    │  │
   │  │ TLS: Secret axiam-public-tls (cert-manager, Let's Encrypt) │  │
   │  └───────┬──────────────────────────────┬─────────────────────┘  │
   │          │ /            (HTTP)          │ /api /oauth2 /.well-known
   │          ▼                              │ (HTTPS, verified against
   │  ns axiam                               │  the in-cluster CA)
   │  ┌───────────────┐    ┌─────────────────▼──────────────────┐     │
   │  │ axiam-frontend│    │ axiam-server ×1                    │     │
   │  │ nginx, SPA    │    │ REST :8090 TLS1.3 · gRPC :50051    │     │
   │  │ :8080         │    │ leaf: Secret axiam-server-tls      │     │
   │  └───────────────┘    │ (cert-manager, issuer axiam-ca)    │     │
   │                       └──┬──────────┬──────────┬───────────┘     │
   │                          │8000      │5671 amqps│8200 https       │
   │                   ┌──────▼───┐ ┌────▼─────┐ ┌──▼────────────┐    │
   │                   │ surrealdb│ │ rabbitmq │ │ vault (Raft)  │    │
   │                   │ surrealkv│ │ TLS 1.3  │ │ TLS 1.3       │    │
   │                   │ PVC 10Gi │ │ PVC 5Gi  │ │ PVC 1Gi       │    │
   │                   └──────────┘ └──────────┘ └───────────────┘    │
   │                                                                  │
   │  ns cert-manager: cert-manager · ClusterIssuers:                 │
   │    letsencrypt-http01 (default) │ letsencrypt-dns01-duckdns (opt)│
   │    axiam-selfsigned → axiam-ca (private CA for every internal leg)│
   │                                                                  │
   │  host: duckdns cron · k3s.service · OpenTofu + state (encrypted) │
   └──────────────────────────────────────────────────────────────────┘

   Not routed: /health, /ready, /health/jobs, gRPC (unless §3 D6 opted in).
   Not forwarded at the router: anything but 80 and 443.
```

Hop count from a browser to `axiam-server`: **one** (ingress-nginx), so
`TRUSTED_HOPS=0`. The frontend's nginx proxies nothing on this topology — the
ingress routes `/api` past it — so `AXIAM_BACKEND_*` are irrelevant here, as
they already are in the shipped `k8s/`.

---

## 3. Decisions

Each decision names the alternative that was rejected and why. The executing
session may revisit a decision only when it finds the assumption behind it to
be false on the real cluster, and then must record the new reasoning in the
operator guide's own decision table.

### D1 — k3s, installed with Traefik and ServiceLB disabled

`curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable traefik --disable servicelb" sh -`,
pinned to a specific `INSTALL_K3S_VERSION` in the script rather than whatever
is current the day it runs. Raspberry Pi OS needs two things k3s does not do
for you: `cgroup_memory=1 cgroup_enable=memory` appended to
`/boot/firmware/cmdline.txt` (without it the kubelet refuses to start on a
Pi), and the default `dphys-swapfile` swap disabled (the kubelet fails with
swap enabled unless told otherwise, and telling it otherwise on an 8 GB node
is the wrong trade). Both are the job of `00-host-prepare.sh`, which must be
idempotent and must refuse to proceed if a reboot is pending after editing
`cmdline.txt`.

Rejected: minikube, MicroK8s, kubeadm — §0.1.

### D2 — ingress-nginx as a hostNetwork DaemonSet; not Traefik, not a `LoadBalancer`

The shipped `k8s/ingress.yml` is `ingressClassName: nginx` with ingress-nginx
annotations, and `allow-ingress-to-server.yml` / `allow-ingress-to-frontend.yml`
select the namespace `ingress-nginx` by name. Installing the controller into
that namespace with that class makes every shipped object work as written.
Traefik would mean rewriting the Ingress (or CRDs), the two NetworkPolicies
and the gRPC route, and forking the topology the design document just
unified.

**hostNetwork mode is not a convenience, it is what keeps invariant 1
true.** The alternatives on a single node all put something between the
client and the controller: k3s ServiceLB (klipper-lb) is a DaemonSet of
iptables-DNAT pods, MetalLB is another controller, a `NodePort` needs a
non-standard port. With `controller.hostNetwork=true`,
`controller.kind=DaemonSet`, `controller.dnsPolicy=ClusterFirstWithHostNet`
and the controller's `Service` reduced to `ClusterIP` (or disabled), the
controller binds the node's 80/443 directly and **the client's address is the
socket peer**. That is the property `TRUSTED_HOPS=0` rests on. The operator
guide must include the Pi guide's §6.3 two-address check as an acceptance
step, not a suggestion; the controller also needs `use-forwarded-headers:
"false"` in its ConfigMap so it never trusts an `X-Forwarded-For` a client
sent — it appends the real peer to the right, which is what the extractor
reads.

Rejected: Traefik (bundled, would fork the manifests); ServiceLB/MetalLB (a
hop whose source-IP behaviour is a setting, not a guarantee).

### D3 — cert-manager owns ACME and the private CA; the backend leg uses the private CA

Two issuers, both created by OpenTofu in stage 10:

- **`letsencrypt-http01`** (`ClusterIssuer`, ACME, solver `http01` with
  `ingress.class: nginx`). Works because ingress-nginx listens on the node's
  port 80. Default.
- **`letsencrypt-dns01-duckdns`** — optional, for the ISP-blocks-80 case the
  Pi guide §4.4 covers. cert-manager has no built-in DuckDNS solver; the
  community webhook `cert-manager-webhook-duckdns` exists and is arm64-buildable
  but is a third-party image. The session must evaluate it, pin a digest if it
  adopts it, and otherwise document the manual DNS-01 fallback (a
  `Certificate` can be issued with the `cmctl`/`kubectl cert-manager` plugin
  against a manual DNS record, renewed by the operator). Do not make it the
  default; do not ship an unpinned image.
- **`axiam-selfsigned` → `axiam-ca`** — a self-signed root `Certificate` in
  `cert-manager`'s namespace, an `Issuer`/`ClusterIssuer` backed by it, and
  `Certificate`s for **`axiam-server`** (dnsNames `axiam-server`,
  `axiam-server.axiam.svc`, `axiam-server.axiam.svc.cluster.local`), **`vault`**
  (→ Secret `vault-tls`, keys `tls.crt`/`tls.key`, matching the shipped
  `vault.hcl`), and **`rabbitmq`** (→ Secret `rabbitmq-broker-tls` with
  `ca.crt` — the shipped server Deployment projects exactly that key). The CA
  certificate is also written to a `ConfigMap`/`Secret` the server mounts, so
  `AXIAM__AUTH__VAULT_CA_CERT_PATH` and `AXIAM__AMQP__TLS__CA_CERT_PATH` (and
  `AXIAM__PKI__VAULT_CA_CERT_PATH` if CA custody is Vault) can point at it.

**Why the backend leg is private rather than the public leaf** (a deliberate
difference from the Pi guide §4): `public-backend-tls-design.md` §3.1 already
says the public-leaf reuse was a *Pi-without-a-CA* expedient and that on
Kubernetes "a service mesh or cert-manager" would issue the backend
certificate. Concretely, ingress-nginx verifies an upstream via
`proxy-ssl-verify: "on"` + `proxy-ssl-secret: <ns>/<secret>`, and that Secret
must hold a **client** keypair as well as `ca.crt`; verifying against the
public roots would mean minting a client certificate for the ingress from
nowhere. With `axiam-ca` the ingress simply gets its own leaf from the same
issuer (`axiam-ingress-client`, presented as a client certificate the server
ignores under `CLIENT_AUTH=off`) and `ca.crt` is the CA it already trusts.
Annotations on the shipped Ingress, via the overlay:
`nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"`, `proxy-ssl-verify:
"on"`, `proxy-ssl-secret: "axiam/axiam-ingress-client"`, `proxy-ssl-name:
"axiam-server.axiam.svc"`. The session must confirm these four names against
the ingress-nginx version it pins; they have been stable for years but the
plan does not get to assume.

**Renewal, both legs.** cert-manager rewrites the `Secret`; the kubelet
refreshes a Secret volume within its sync period (about a minute) unless the
mount uses `subPath`, which the overlay therefore must not; the server's
periodic poll (`AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS`, default hourly, must
not be `0`) swaps the leaf behind the `ArcSwap` with no restart. Vault and
RabbitMQ do **not** hot-reload: the guide must state that their pods need a
rolling restart after their internal leaf renews, and the cert-manager
`Certificate` duration for those two should be long (one year) so it is a
yearly, scheduled event, not a surprise. cert-manager's `reloader`-style
annotation-driven restarts are an option the session may evaluate.

### D4 — Vault: the shipped StatefulSet, fixed to admit; static periodic token first, Kubernetes auth as a documented phase 2

`k8s/vault/statefulset.yml` and `docker/vault/vault.hcl` are in this repo, and
`k8s/vault/README.md` already says the StatefulSet is the honest
single-node shape. The alternative — HashiCorp's Helm chart in its own
namespace — sidesteps the admission problems of §4 F2 but moves Vault out of
the `axiam` namespace, which changes `AXIAM__AUTH__VAULT_ADDR`, requires a
cross-namespace egress rule and forks the manifests the repo documents. Fix
the shipped one instead; if the fixes turn out larger than F2 describes,
fall back to the chart and say so.

Authentication of the server to Vault, in two phases:

- **Phase 1 (this plan delivers):** a periodic token (`-period=768h`) with the
  `axiam` policy, issued by OpenTofu's `vault_token` resource after the
  ceremony and written into `axiam-secrets` as `AXIAM__AUTH__VAULT_TOKEN`.
  This mirrors the Pi guide §7.3 exactly, is what the shipped `secret.yml`
  documents, and is what `just vault-status` knows how to check. The
  `vault_token` resource keeps the token in state — one more reason the state
  is a secret (D5).
- **Phase 2 (documented, optional):** the Kubernetes auth method plus the
  Vault Agent Injector, per `docs/deployment/vault.md` §5.6. AXIAM's provider
  takes a token and does not perform the login itself, and the distroless
  image has no shell to read a file into an environment variable, so phase 2
  means the `file` provider with agent-templated secrets. **Check before
  recommending it:** `AXIAM__PKI__CA_KEY_STORE=vault` writes CA keys into Vault
  at runtime using `AXIAM__PKI__VAULT_TOKEN`; the injector's rotating token
  would have to be surfaced to that variable as well, and the session must
  verify from `crates/axiam-pki/src/ca_key_store.rs` and the server's
  `custodians_from_env` whether a file path is accepted anywhere. If not,
  phase 2 is "file provider for deployment secrets, database custody for CA
  keys", and the guide must say that plainly.

Auto-unseal: unchanged from the Pi guide §7.1 — GCP KMS recommended, the
`seal` block is already stubbed in both `vault.hcl` copies, and without it the
operator is running a manually-unsealed Vault and must write that down. The
overlay must make the `seal` block a documented patch, not a hard-coded
cloud dependency.

### D5 — OpenTofu on the Pi, local encrypted state, three stages, one wrapper

**Where it runs:** on the Pi, against the k3s kubeconfig at
`/etc/rancher/k3s/k3s.yaml` (copied to the operator's `~/.kube/config` with
mode 600 by the install script). Running it from a laptop is possible over a
LAN or Tailscale route to 6443 but adds a second machine that holds the state
and the Vault token; the plan does not choose that for the operator, and the
guide says how to do it if they want to.

**State:** local backend, directory `~/axiam-infra/state/` outside the
repository, `encryption` block in a `.tofu` file (passphrase or PBKDF2 key
provider, the passphrase held like an unseal share — off the Pi). Backed up
with the Vault Raft snapshots by `04-backup.sh`. The `.gitignore` gains
`*.tfstate`, `*.tfstate.*`, `.terraform/`, `.terraform.lock.hcl` **is**
committed (provider pins), `*.auto.tfvars` ignored with an
`example.tfvars` committed.

**Stages**, because provider configuration cannot depend on resources the same
root module creates (the Kubernetes provider needs a cluster; the Vault
provider needs an initialised, unsealed Vault with a token):

| Stage | Providers | Creates | Precondition |
| --- | --- | --- | --- |
| `10-platform` | helm, kubernetes, kubectl (for CRDs/manifests) | ingress-nginx (D2 values), cert-manager + CRDs, the four issuers of D3, the `duckdns-token` Secret if DNS-01 | k3s up, kubeconfig present |
| `20-axiam` | kubernetes, kustomization, random, tls | `random_password`s → `surrealdb-credentials`, `rabbitmq-credentials`, `axiam-secrets` (DB pair, AMQP URL, Vault token placeholder); `tls_private_key` (Ed25519) → JWT PEM inputs for seeding; `Certificate`s for server, vault, rabbitmq, ingress client; the rendered `k8s/overlays/rpi5-k3s` | stage 10 applied; cert-manager webhooks ready |
| *ceremony* | — (human, `02-vault-ceremony.sh`) | initialised Vault, 5 shares handed out, root token in the operator's hands for the next twenty minutes | stage 20's Vault pod Running |
| `30-vault-config` | vault (via a `kubectl port-forward` the wrapper opens), kubernetes | KV v2 mount, `axiam` policy from `docker/vault/axiam-policy.hcl`, periodic token → patched into `axiam-secrets`; `terraform_data` runs `scripts/vault-seed.sh` with the JWT PEMs from stage 20 outputs | ceremony done, `VAULT_TOKEN` exported for this run only, then revoked by the wrapper |

The wrapper `run.sh <stage> <plan|apply|destroy>` does the boring parts —
`tofu init`, the port-forward for stage 30, refusing `destroy` on stage 20
without an explicit `--i-understand-this-deletes-the-datastore` flag (the
PVCs are the datastore), and printing the `just vault-status`-equivalent at
the end of stage 30.

Rejected: a single root module (impossible for the reason above); remote
state in a cloud bucket (fine, but a cloud dependency the operator did not ask
for; documented as an option); `kubernetes_manifest` per object (works, more
noise, CRD ordering hazards).

### D6 — gRPC stays opt-in and goes through the ingress

A second `Ingress` object in the overlay, disabled by default (an overlay
component or a `tofu` variable), with `backend-protocol: "GRPCS"`, the same
`proxy-ssl-*` annotations as D3, and exactly the three paths the Pi guide
§14.3 allows. `AXIAM__GRPC_TLS_CERT_PATH`/`KEY_PATH` point at the same
`axiam-server-tls` mount (one certificate, both listeners, one poll — Pi guide
§14.5), and `AXIAM__GRPC__STRICT_REVOCATION=true` when published (§14.6).

### D7 — Single replica, no HPA, on the Pi

The overlay sets `replicas: 1` for `axiam-server` and `axiam-frontend` and
**removes** the HPA (`$patch: delete`); k3s bundles metrics-server, so the HPA
would function, and at `minReplicas: 2` it would immediately undo the
replica patch. The Pi guide §14.6's session-validation-cache note assumes one
replica; this makes that assumption true by construction.

### D8 — What is a base fix and what is an overlay

A change goes into `k8s/` (the base) when it is wrong on **every** cluster;
into `k8s/overlays/rpi5-k3s/` when it is specific to one Pi. §4 labels each
finding accordingly. Base fixes are their own commits with the same
commentary style the existing manifests use (an ID, the reason, the failure
it prevents) so they can be reviewed and merged independently of the Pi work.

---

## 4. Findings in the shipped `k8s/` that this work must resolve

These were found by reading at `7505ae5`. Each must be **confirmed on the real
cluster** (or by `kubeconform`/admission dry-run where that is possible)
before it is acted on; a finding that turns out not to reproduce is recorded
as such, not silently dropped.

| # | Finding | Evidence | Scope (D8) |
| --- | --- | --- | --- |
| **F1** | **The server cannot reach Vault.** `server-egress.yml` allows egress to SurrealDB:8000, RabbitMQ:5671, public 443 and SMTP; nothing on 8200. With `default-deny-all` and `AXIAM__AUTH__SECRET_PROVIDER: "vault"` in the ConfigMap, the shipped deployment fails at startup on the first secret fetch. There is also no `allow-ingress-to-vault.yml` for the receiver side (the SEC-053 comment in `kustomization.yml` explains why both halves are needed). | `grep -rn 8200 k8s/network-policy/` → nothing | **Base** |
| **F2** | **The Vault StatefulSet does not admit under `restricted`.** It adds `IPC_LOCK` (restricted permits adding only `NET_BIND_SERVICE`) and sets no `seccompProfile` (restricted requires `RuntimeDefault` or `Localhost`). Fix: `disable_mlock = true` in the k8s `vault.hcl` (HashiCorp recommends exactly this for integrated storage, whose data is already on disk), drop the `add`, add the seccomp profile and `runAsGroup`. The Compose `vault.hcl` (`disable_mlock = false`) and compose file can stay as they are — Docker has no PSA. | `k8s/vault/statefulset.yml` L130; `k8s/namespace.yml` enforce label | **Base** |
| **F3** | **The 443-egress exceptions name the wrong CIDRs for k3s.** `server-egress.yml` excludes `10.244.0.0/16` and `10.96.0.0/12`; k3s defaults are pod `10.42.0.0/16` and service `10.43.0.0/16`. Left as shipped, the "external HTTPS" rule lets the server reach any in-cluster service on 443 — the lateral-movement hole the exceptions exist to close. The base's own comment says the operator MUST override; the overlay does. | `k8s/network-policy/server-egress.yml` | **Overlay** (base comment already correct) |
| **F4** | **Two Secrets are consumed and never produced.** `vault-tls` (Vault's listener) and `rabbitmq-broker-tls` (broker leaf + `ca.crt`, also projected into the server pod) are referenced by the StatefulSets and the Deployment; nothing in `k8s/` issues them, and the RabbitMQ manifest's comment names cert-manager as the intended issuer. cert-manager is therefore a hard requirement of the shipped manifests. Fix: ship example `Certificate`/`Issuer` manifests under `k8s/certs/` (not in the base `kustomization.yml`, since the CRDs may be absent) and reference them from `docs/deployment/README.md`; the overlay uses them. | `k8s/rabbitmq/statefulset.yml` volumes; `k8s/vault/statefulset.yml` volumes | **Base (examples) + Overlay** |
| **F5** | **The backend TLS leg is not enabled on Kubernetes.** No `AXIAM__SERVER__TLS__*` in the ConfigMap, no certificate mounted into the server pod, no `backend-protocol` on the Ingress. `public-backend-tls-design.md` §1.3 says "put TLS on the backend leg in both"; today only Compose has it. Fix per D3. | `k8s/server/configmap.yml`, `k8s/ingress.yml` | **Base** (mount + env, with the Certificate from F4) — the Ingress annotations are base too, since they are ingress-nginx-generic |
| **F6** | **Two replicas and an HPA on one node.** See D7. | `k8s/server/deployment.yml`, `hpa.yml`, `frontend/deployment.yml` | **Overlay** |
| **F7** | **The mandatory runtime settings are absent and the image name is a placeholder.** None of Pi guide §5.2's six variables is in the ConfigMap or Deployment; `image:` is `ghcr.io/OWNER/server:1.0.0-beta15` whereas the registry path is `ghcr.io/ilpanich/axiam/server`. The placeholder is deliberate in the base (any fork); the overlay sets the real names and the six values; the base gains the variables **commented** with the Pi guide's explanations, so the next reader finds them. | `k8s/server/configmap.yml`, `deployment.yml` | **Overlay** (values) + **Base** (commented keys) |
| **F8** | **Credentials are blank by design, and honoured only on first boot.** `surrealdb-credentials`, `rabbitmq-credentials`, `axiam-secrets` ship empty. OpenTofu fills them (§0.2), with `ignore_changes`/`prevent_destroy`, and the guide must carry the Pi guide §5.1 warning verbatim: rotating them means wiping the volume. | `k8s/*/secret.yml`; `justfile` `prod-up` guard | **Tofu stage 20** |
| **F9** | **Image architecture and tag pins.** `hashicorp/vault:1.20`, `surrealdb/surrealdb:v3`, `rabbitmq:4-management-alpine`, ingress-nginx, cert-manager and the two AXIAM images all publish `linux/arm64`. `surrealdb:v3` is a moving major tag; the storage-engine note in `docs/deployment/README.md` pins behaviour to 3.2.x measurements, so the overlay should pin a minor (`v3.2`) or a digest and say why. | `k8s/surrealdb/statefulset.yml` | **Overlay** (pin) |
| **F10** | **CA-key custody variables.** If the guide recommends `AXIAM__PKI__CA_KEY_STORE=vault` (it should, for parity with Vault holding everything else), the server needs `AXIAM__PKI__VAULT_ADDR`, `_TOKEN`, `_CA_CERT_PATH`; the shipped policy already grants the `ca-keys` prefix. The session must check `custodians_from_env` in `crates/axiam-server/src/main.rs` for the exact names and defaults rather than trusting `docs/pki/README.md` alone. | `docs/pki/README.md` §"Configuring Vault custody" | **Overlay** |

---

## 5. Deliverables

Paths are proposals; the executing session keeps them unless a repository
convention it discovers says otherwise, and records any rename.

```
infra/rpi5-k3s/
├── README.md                      # pointer to the operator guide + layout of this tree
├── run.sh                         # stage wrapper (D5): init/plan/apply/destroy, port-forward, guards
├── scripts/
│   ├── 00-host-prepare.sh         # apt deps, cmdline.txt cgroups, swap off, NVMe/disk check, reboot gate
│   ├── 01-install-k3s.sh          # pinned k3s, --disable traefik,servicelb; kubeconfig; tofu + kubectl + helm arm64
│   ├── 02-vault-ceremony.sh       # init 5/3 → prints once; unseal ×3; guidance text; NEVER writes shares to disk
│   ├── 03-axiam-bootstrap.sh      # setup token from pod log → POST bootstrap; POST federation-configs from a YAML you edit
│   ├── 04-backup.sh               # raft snapshot + local-path PVC copy + tofu state + off-device rsync target
│   └── 05-verify.sh               # layered probes (port-forward :8090 /health; public discovery; SPA), two-IP TRUSTED_HOPS check,
│                                  # PSA/netpol probes, `vault-status` equivalent, cert-manager Ready conditions
└── tofu/
    ├── 10-platform/               # ingress-nginx (hostNetwork values), cert-manager (+CRDs), issuers, optional duckdns webhook
    ├── 20-axiam/                  # random/tls → Secrets; Certificates; kustomization_overlay of k8s/overlays/rpi5-k3s
    ├── 30-vault-config/           # vault mount, policy from docker/vault/axiam-policy.hcl, vault_token → Secret; seed via script
    ├── modules/                   # only if two stages genuinely share a shape; do not pre-abstract
    ├── example.tfvars             # host, email, tag, cidrs, issuer choice, grpc_public=false, seal={}
    └── encryption.tofu            # OpenTofu-only state encryption (ignored by Terraform)

k8s/
├── certs/                         # F4: example Certificate/Issuer manifests (not in the base kustomization)
├── network-policy/allow-ingress-to-vault.yml   # F1
├── network-policy/server-egress.yml            # F1 (+8200), base comment about k3s CIDRs
├── vault/statefulset.yml                       # F2
├── server/{configmap,deployment}.yml           # F5 (TLS mount+env), F7 (commented keys)
├── ingress.yml                                 # F5 annotations (backend HTTPS + verify)
└── overlays/rpi5-k3s/
    ├── kustomization.yml          # base ../../ ; images: real names + pinned tag; patches below
    ├── replicas-and-hpa.yml       # F6 / D7
    ├── configmap-env.yml          # F7: the six mandatory values + Vault/PKI/AMQP CA paths (F10)
    ├── network-policy-cidrs.yml   # F3
    ├── ingress-host.yml           # host axiam-iam.duckdns.org, cert-manager annotation, TLS secret name
    ├── ingress-grpc.yml           # D6, off by default (component)
    ├── vault-seal.yml             # D4: documented seal patch, empty by default
    └── surrealdb-pin.yml          # F9

docs/deployment/rpi5-k3s.md        # the operator guide — the k3s counterpart of the Pi guide, same section order
                                   # where the subject is the same, a §0 delta table (see §0.1), and its own
                                   # troubleshooting table. Links to, never duplicates, the Pi guide for §3, §9–§12.
claude_dev/rpi5-prod-google-federation-guide.md   # §17 last bullet gains a pointer to the k3s guide
docs/deployment/README.md          # Kubernetes section links the guide and k8s/certs/
.gitignore                         # tfstate, .terraform/, *.auto.tfvars
```

**Not deliverables:** any change to Rust code, `Cargo.*`, the website, the
SDK contract, or the Compose path. If the session finds a code defect (for
example a config name the docs and the code disagree on), it records it in
the guide's troubleshooting table and in the final report, and does not fix
it in this branch.

---

## 6. Execution waves for the executing session

Do them in order. Each wave ends with a commit; §7 says what "verified" can
mean in a sandbox that has no cluster.

**Wave 0 — boot and confirm.** `sage_inception` first (CLAUDE.md). Read this
document, the Pi guide, `public-backend-tls-design.md` §1–§4 and §11, all of
`k8s/`, `docs/deployment/README.md` §Kubernetes and §Network policies,
`docs/deployment/vault.md` §5, `docs/pki/README.md` §Vault custody, and
`docker/vault/axiam-policy.hcl`. Re-verify every row of §4 against the tree
and write down, in a scratch note, which ones still hold, which are already
fixed on `main`, and which you cannot confirm without a cluster. Then try to
install the tooling: `tofu`, `kubectl`, `kustomize` (or `kubectl kustomize`),
`kubeconform`, `helm`, `shellcheck`. The sandbox proxy has blocked GitHub
release downloads before (CLAUDE.md, the swagger-ui note); if a binary cannot
be fetched, record it and move on — §7 tells you what to do instead.

**Wave 1 — base fixes (D8).** F1, F2, F4-examples, F5, F7-commented-keys, in
separate commits with the repository's manifest-comment style (an identifier,
the reason, the failure the change prevents). Make sure `kubectl apply -k
k8s/` still renders (the `certs/` directory is *not* in the base
kustomization). Trivy's config scan in CI (`ci.yml`, advisory) also scans
`.tf` files; do not introduce a HIGH/CRITICAL it would flag without a comment
saying why.

**Wave 2 — the overlay.** `k8s/overlays/rpi5-k3s/` per §5, one patch file per
concern. Render it, diff the render against the base render, and check that
every difference maps to a §4 row or a §3 decision — anything unexplained is a
mistake.

**Wave 3 — host scripts.** `00`–`05` per §5. Bash with `set -euo pipefail`,
idempotent, `shellcheck`-clean where the tool is available, and every
destructive step behind an explicit flag. `02-vault-ceremony.sh` must never
write a share or the root token to disk; it prints, it waits for the operator
to confirm they have recorded the shares, and it offers to unseal. Reuse
`scripts/vault-seed.sh` and `scripts/vault-policy.sh`; do not reimplement them.

**Wave 4 — OpenTofu.** Stages 10 → 20 → 30 and the wrapper, per D5. Pin every
provider in `.terraform.lock.hcl` and every chart version in the HCL. Every
`random_password`/`tls_private_key`/`vault_token` carries the lifecycle
guards of §0.2. `tofu fmt` and `tofu validate` on each stage (or the §7
fallback). Write `example.tfvars` with the Pi guide's values
(`axiam-iam.duckdns.org`, etc.) so the operator's diff from example to real
is small.

**Wave 5 — the operator guide.** `docs/deployment/rpi5-k3s.md`, in the Pi
guide's voice and section order: §0 delta table, §1 prerequisites (the Pi
guide's plus the cgroup/swap points of D1), §2 topology (the §2 diagram),
§3 DuckDNS (link), §4 certificates (D3, both legs, renewal semantics
including the Vault/RabbitMQ restart caveat), §5 bring-up (`run.sh` stages in
order with the ceremony in the middle), §6 the three settings worth
understanding (`TRUSTED_HOPS` derivation for hostNetwork ingress; why the
backend leg is private here; why the state file is a secret), §7 Vault
(ceremony, phase 1 token, phase 2 pointer, auto-unseal, snapshots), §8
reboots (k3s.service; sealed-Vault symptom), §9–§12 bootstrap, providers,
admin UI, verification — link to the Pi guide, do not copy, §13 mTLS for
devices (a second hostname still cannot go through the ingress; a TCP
passthrough or a hostPort on the server is the k8s shape — describe, do not
build), §14 gRPC (D6), §15 upgrading from the Compose Pi (Raft snapshot
restore into the new Vault; PVC-less migration of SurrealDB via export/import
— **verify the tooling exists before promising it**, otherwise say "fresh
bootstrap, users re-enrol"), §16 troubleshooting, §17 before-you-call-this-
production. Then the two link edits in §5.

**Wave 6 — verification and report.** Run everything §7 allows, fix what it
finds, update this document's status line to `EXECUTED <date>` with a summary
paragraph in the style of the other executed plans in `claude_dev/`
(see `website-security-beta15-update-plan.md`'s header for the shape), and
finish with a report that lists **what was verified how, and what could not
be verified in the sandbox and therefore must be verified on the Pi first**.
Do not open a pull request unless asked.

---

## 7. Verification — what "done" can mean without a Pi

The sandbox has no Kubernetes cluster and no Docker daemon, and may not be able
to download release binaries. So:

| Check | If the tool is available | If it is not |
| --- | --- | --- |
| Manifests render | `kubectl kustomize k8s/` and `k8s/overlays/rpi5-k3s/` produce YAML; `kubeconform -strict -ignore-missing-schemas` passes on both | `python3 -c 'import yaml; list(yaml.safe_load_all(...))'` on every file for syntax; a hand-checked render of the overlay's patches against the base (state that this is what was done) |
| Admission under `restricted` | `kubeconform` with the PSA schemas, or `kubectl --dry-run=server` on a cluster (not here) | A written checklist per pod against the restricted profile's field list, in the guide's troubleshooting section; F2 is the known failure to look for |
| HCL | `tofu fmt -check`, `tofu init -backend=false`, `tofu validate` per stage | The wrapper's first action on the Pi is exactly those three; the guide says so, and the session reads its own HCL twice |
| Shell | `shellcheck -S warning` | `bash -n` on every script and a re-read |
| Docs | `scripts/check-doc-links.sh` (scans `docs/**`, so the new guide is covered) | — |
| The invariants of §1 | A table in the guide's §17 mapping each invariant to the file and line that enforces it | Same |

Whatever could not run is listed by name in the final report and at the top
of the operator guide, so the person who first runs this on hardware knows
what has never been executed. **Claiming a verification that did not happen
is the one failure mode this plan cannot recover from.**

---

## 8. Guardrails for the executing session

- **Read the repo's `CLAUDE.md` first and obey it**: SAGE boot; feature
  branch; clear commit messages; no model identifiers in commits or files;
  no PR unless asked. No Rust compiles are needed for this work, so the cargo
  hygiene rules do not bite, but if you do touch `cargo`, they do.
- **No secrets in the tree.** `**/*.pem` and `**/*.key` are already ignored;
  add the Terraform patterns. `example.tfvars` holds placeholders only. No
  real DuckDNS token, no real email, no client secret, anywhere.
- **Reuse before writing.** `scripts/vault-seed.sh`, `scripts/vault-policy.sh`,
  `docker/vault/axiam-policy.hcl`, `scripts/vault-status.py` are the
  canonical implementations. If one cannot be reused as-is (for example
  `vault-status.py` assumes `docker exec`), wrap it, do not fork it, and note
  the limitation.
- **Pin everything**: k3s version, chart versions, image tags (digests where a
  moving tag is all a project publishes), provider versions. A plan that
  installs "latest" is not reproducible next month.
- **The Pi guide's ethos is the style guide**: derive from the code, say when
  the code and expectation disagree, explain *why* beside every non-obvious
  value, and never offer a `-k`/`--insecure`/"disable verification" escape
  hatch.
- **Scope discipline**: §5 lists what is and is not a deliverable. A code
  defect is reported, not fixed here. A finding that contradicts a decision in
  §3 is recorded with its evidence and the decision is revisited in the guide's
  decision table — not silently changed.
- **Honesty about the sandbox** (§7). The person reading your final report
  will run this on a Pi they own with real IdP accounts; what you say was
  verified must have been.

---

## 9. The kick-off prompt for the executing session

Start a new session on the repository, on a fresh feature branch, and paste
this as the first message.

```text
Read CLAUDE.md and boot per its instructions before anything else.

You are executing the plan in claude_dev/rpi5-k3s-opentofu-plan.md. Read it
in full, then the documents its Wave 0 names, before writing a single file.
The plan is the specification: its §1 invariants are non-negotiable, its §3
decisions hold unless you find on evidence that an assumption behind one is
false (then record the evidence and the revised reasoning in the operator
guide's decision table), its §4 findings must each be re-confirmed against
the tree before being acted on, and its §5 lists exactly what you deliver
and what you do not touch.

Work the six waves of §6 in order, one or more commits per wave, on this
branch. Apply §7 literally: run every check whose tool you can install in
this sandbox; where a tool cannot be installed, do the stated fallback and
record — in your final report and at the top of docs/deployment/rpi5-k3s.md
— exactly which checks were not executed and must be run on the Pi first.
Never state that something was verified when it was not.

Constraints: no changes to Rust code, Cargo files, the website, the SDK
contract or the Compose path; no secrets or real identifiers in the tree;
no PR unless I ask; reuse scripts/vault-seed.sh, scripts/vault-policy.sh and
docker/vault/axiam-policy.hcl rather than reimplementing them; pin every
version; write in the voice of claude_dev/rpi5-prod-google-federation-guide.md.

When Wave 6 is done, update the plan's status header to EXECUTED with a
summary in the style of the other executed plans in claude_dev/, push the
branch, and give me a report with three sections: what was built (by path),
what was verified and how, and what could not be verified here and why.
```

---

## Appendix A — Facts pinned from the tree at `7505ae5`, for the executing session's convenience

| Fact | Where |
| --- | --- |
| Images: `ghcr.io/ilpanich/axiam/server`, `ghcr.io/ilpanich/axiam/frontend`; tag = workspace version without `v`; `linux/amd64` + `linux/arm64` one manifest list; no `latest` | `.github/workflows/release.yml`; `justfile` `prod-up`; Pi guide §1 |
| Current release `1.0.0-beta15`; base manifests already reference that tag with the `OWNER` placeholder | `Cargo.toml` L60; `k8s/server/deployment.yml` |
| Server TLS: `AXIAM__SERVER__TLS__{ENABLED,CERT_PATH,KEY_PATH,CLIENT_AUTH,RELOAD_INTERVAL_SECS}`; reload on `SIGHUP` and on a periodic `stat` poll; both REST and gRPC listeners share one `ReloadableCertResolver` when pointed at the same files | `docker/docker-compose.prod.yml` L262–283; `crates/axiam-server/src/tls.rs` (`spawn_leaf_reloader`, `reload_leaf_certificate`) |
| gRPC TLS: flat `AXIAM__GRPC_TLS_CERT_PATH` / `AXIAM__GRPC_TLS_KEY_PATH`, both or neither, panics on an unreadable file; `AXIAM__GRPC__STRICT_REVOCATION` | `crates/axiam-api-grpc/src/server.rs` L32, L102, L187; Pi guide §14.4 |
| Vault provider: `AXIAM__AUTH__SECRET_PROVIDER=vault`, `VAULT_ADDR`, `VAULT_MOUNT`, `VAULT_PATH`, `VAULT_TOKEN`, optional `AXIAM__AUTH__VAULT_CA_CERT_PATH`; provider takes a token, does not log in itself | `crates/axiam-auth/src/secrets.rs` L400 and §5.6 of `docs/deployment/vault.md` |
| CA-key custody: `database` (default) / `vault` / `vault_pki`; `AXIAM__PKI__VAULT_ADDR`, `_TOKEN`, `_MOUNT`, `_PREFIX` (`axiam/ca-keys`), `_CA_CERT_PATH`; address+token imply `vault`; `CA_KEY_STORE=vault` without them is a startup failure | `crates/axiam-pki/src/ca_key_store.rs`; `docs/pki/README.md`; `crates/axiam-server/src/main.rs` L1088–1114 |
| Shipped Vault policy grants read on `secret/data|metadata/axiam` and create/read/update/delete under the `ca-keys` prefix; `scripts/vault-policy.sh` writes it | `docker/vault/axiam-policy.hcl`; `scripts/vault-policy.sh` |
| Seeder waits for an **active** node (200 on `sys/health`), refuses on 429/501/503/000, writes with KV v2 `cas` | `scripts/vault-seed.sh` §1–2 |
| Vault k8s manifest: `hashicorp/vault:1.20`, Raft at `/vault/data`, `node_id vault-0`, TLS 1.3 listener from Secret `vault-tls` (`tls.crt`/`tls.key`), `runAsUser 100`, `fsGroup 1000`, no liveness probe on purpose, `IPC_LOCK` added | `k8s/vault/statefulset.yml` |
| RabbitMQ: AMQPS 5671 only, TLS 1.3, vhost `axiam`, Secret `rabbitmq-broker-tls` (`ca.crt`/`tls.crt`/`tls.key`), UID 999 | `k8s/rabbitmq/statefulset.yml` |
| SurrealDB: `surrealkv:/data/surreal.db`, UID 65532, PVC 10Gi | `k8s/surrealdb/statefulset.yml` |
| Server pod: UID/GID/fsGroup 65532, read-only root, key-material Secret mounted 0440 at `/etc/axiam/secrets` (the `file` provider's directory), broker CA at `/etc/axiam/broker-tls/ca.crt` | `k8s/server/deployment.yml` |
| NetworkPolicies: default-deny both ways; DNS to `kube-system`; ingress from namespace `ingress-nginx` to server:8090 and frontend:8080; server → surrealdb:8000, rabbitmq:5671, public 443 (minus RFC1918/CGN/10.244.0.0/16/10.96.0.0/12), SMTP to a TEST-NET placeholder | `k8s/network-policy/*.yml` |
| PSA `restricted` enforced, version `v1.29`, on namespace `axiam` | `k8s/namespace.yml` |
| Bootstrap gate: `AXIAM_BOOTSTRAP_ADMIN_EMAIL` must match, or the one-time `setup_token` from the first-boot log; `POST /api/v1/admin/bootstrap` is one-shot (`bootstrap_lock:global`) | `crates/axiam-api-rest/src/handlers/bootstrap.rs`; Pi guide §9 |
| Redirect URI for every IdP but Apple: `https://<host>/auth/sso/callback`; Apple: `https://<host>/api/v1/auth/federation/oidc/callback/form` | Pi guide §10 |
| CI's Trivy config scan covers Dockerfiles, k8s manifests **and Terraform files**, advisory, HIGH/CRITICAL to SARIF | `.github/workflows/ci.yml` L381–400 |
| `scripts/check-doc-links.sh` scans `docs/**/*.md` and `claude_dev/security-audit.md` only — this plan is not link-checked by CI; the new guide under `docs/deployment/` will be | `scripts/check-doc-links.sh` |
