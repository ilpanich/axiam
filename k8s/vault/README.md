# Vault manifests

These deploy a **single-node Vault with Raft (integrated) storage**, which is
deliberately the simplest thing that is honestly production-*shaped* rather than
production-*ready*. It gives you a real sealed/unsealed lifecycle, persistent
storage, snapshots (`vault operator raft snapshot save`) and TLS — the parts
that differ from `-dev` mode and that an operator must understand — without
pretending to be an HA cluster.

The single thing that still makes it not production is **auto-unseal**: no
`seal` block is configured, so every restart leaves Vault sealed and AXIAM
unable to start until a human unseals it. `statefulset.yml` carries the
commented `seal` blocks and `docs/deployment/vault.md` §5.3 explains why this
is the step most often deferred and most expensive to defer.

**Upgrading from an earlier revision of these manifests**, which used the `file`
backend at `/vault/file`: the storage backend and the mount path have both
changed, so the existing PVC is not readable by Raft. Migrate with
`vault operator migrate` before applying — see `docs/deployment/vault.md` §5.

For a real deployment, prefer one of:

- **HashiCorp's official Helm chart** (`hashicorp/vault`), with Raft integrated
  storage, 3 or 5 replicas and auto-unseal. That is what most teams should run.
- **Vault Enterprise / HCP Vault**, if you want it operated for you.
- **An existing Vault** your organisation already runs — in which case delete
  this directory entirely and point
  `AXIAM__AUTH__VAULT_ADDR` at it. AXIAM does not care who runs Vault.

What AXIAM actually requires is only this: a KV v2 secret at
`<mount>/<path>` whose fields are named after
`axiam_core::secrets`' constants. Everything else here is convenience.

See [`docs/deployment/vault.md`](../../docs/deployment/vault.md) for the
initialisation ceremony, the auth-method choice, policy, rotation, and examples
for AWS KMS, GCP Secret Manager and PKCS#11.
