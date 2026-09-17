# AXIAM on a Raspberry Pi 5, with k3s and OpenTofu

**The operator guide is [`docs/deployment/rpi5-k3s.md`](../../docs/deployment/rpi5-k3s.md).**
Read that; this file is the map of what is in this directory.

```
infra/rpi5-k3s/
├── run.sh                 stage wrapper: init/plan/apply/destroy, the port-forward, the guards
├── overlay/               the kustomize overlay applied to k8s/ — one patch file per concern
├── scripts/
│   ├── versions.env       every pinned version, in one file
│   ├── _lib.sh            five helpers, sourced by the rest
│   ├── 00-host-prepare.sh cgroups, swap, packages, disk checks, the reboot gate
│   ├── 01-install-k3s.sh  pinned k3s with Traefik and ServiceLB disabled; kubectl, tofu
│   ├── 02-vault-ceremony.sh  5-of-3 Shamir init. Never writes a share to disk.
│   ├── 03-axiam-bootstrap.sh  the two one-shot API calls
│   ├── providers.example.yml  the five identity providers, placeholders only
│   ├── 04-backup.sh       Vault snapshot + datastore export + tofu state, one 0600 archive
│   └── 05-verify.sh       eleven layered checks
└── tofu/
    ├── 10-platform/       ingress-nginx, cert-manager, the four issuers
    ├── 20-axiam/          credentials, the internal certificates, the manifests
    ├── 30-vault-config/   mount, policy, seeding, the server's token
    ├── example.tfvars     copy per stage; NO SECRETS EVER GO IN A TFVARS FILE
    └── encryption.tofu    OpenTofu state encryption, off until you turn it on
```

## The order, and why the ceremony is in the middle

```
  00-host-prepare.sh        (reboot if it says so)
  01-install-k3s.sh
  run.sh 10-platform apply  ingress-nginx, cert-manager, issuers
  run.sh 20-axiam    apply  credentials, certificates, the manifests
  02-vault-ceremony.sh      ← a HUMAN, five shares, printed once
  run.sh 30-vault-config apply
  …then revoke the root token
  03-axiam-bootstrap.sh
  05-verify.sh
```

A provider's configuration cannot depend on a resource the same root module
creates. The Kubernetes provider needs a cluster; the Vault provider needs an
initialised, unsealed Vault and a token. That is why there are three stages
rather than one root module — and why the ceremony sits between two of them
rather than inside any.

**Between stage 20 and stage 30 the server pod sits in
`CreateContainerConfigError`, saying `secret "axiam-vault-token" not found`.**
That is correct. It cannot serve a login before Vault has been initialised and
seeded, and the pod recovers on its own once stage 30 creates the Secret.

## Four things this deployment does NOT automate, on purpose

1. **Installing k3s.** The providers that apply everything else need a cluster to
   talk to. A `terraform_data` wrapping the install script would hide a one-time
   host mutation behind a tool whose entire value is convergence, on something
   that converges on nothing.
2. **The Vault ceremony.** There is no `vault_init` resource and there must not
   be one. `vault operator init` produces five secrets ONCE, to be handed to five
   places that do not fail together; a tool whose job is to record its inputs in
   a state file is the wrong tool for a value whose whole security property is
   that it is not recorded in one place.
3. **Registering the identity providers.** Google publishes no Terraform resource
   for OAuth clients under the Google Auth Platform (`google_iap_client` is
   IAP-only), and GitHub OAuth Apps, Facebook apps and Apple Services IDs have no
   provider at all. Those stay the click-through steps of the Pi guide §10. Only
   Microsoft Entra is automatable, with `azuread_application`.
4. **AXIAM's first-run configuration.** `POST /api/v1/admin/bootstrap` is
   one-shot and fail-closed, with a setup token read from the first-boot log —
   the opposite of a resource that converges. `03-axiam-bootstrap.sh` is honest
   about being a script.

## The state file is a secret

Stage 20's state holds the SurrealDB root password and the RabbitMQ password;
stage 30's holds the server's Vault token, which is a bearer credential for a
Vault containing the OPAQUE setup key. `run.sh` keeps both outside the
repository, in `~/axiam-infra/state/` at mode 0700, and `.gitignore` covers the
patterns anyway. `tofu/encryption.tofu` turns on OpenTofu's state encryption;
read its header before enabling it, particularly the part about migrating an
existing plaintext state.

No secret is ever a tofu **variable**: every value in a `.tfvars` file ends up in
the state. The Vault root token goes in the environment of one command, and the
state passphrase in `TOFU_ENCRYPTION_PASSPHRASE`.

## OpenTofu or Terraform

Either. Nothing here uses OpenTofu-only syntax except `encryption.tofu`, whose
`.tofu` extension Terraform ignores by design, so the same tree is valid under
both. `run.sh` uses whichever binary it finds. `scripts/01-install-k3s.sh`
installs OpenTofu, because that is the default this project picked; the licence
question is the operator's, not this tree's.

## `.terraform.lock.hcl`

Not shipped, and not ignored either. Generating a valid lock file means
downloading each provider and recording its real checksum, and the environment
these files were authored in had no route to either provider registry — a
hand-written one would make `tofu init` fail with a checksum mismatch, which is
worse than none. Every provider is pinned to an EXACT version in each stage's
`versions.tf`, so what you get is reproducible; commit the lock file your first
`run.sh <stage> init` writes, so the checksums are pinned too.
