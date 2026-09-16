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

## `disable_mlock = true`, and why only here

The config in `statefulset.yml` sets `disable_mlock = true`; the Compose copy
(`docker/vault/vault.hcl`) does not, and the difference is deliberate. Pod
Security Admission `restricted` — enforced on the `axiam` namespace by
`k8s/namespace.yml` — permits adding exactly one capability, `NET_BIND_SERVICE`,
so a pod asking for `IPC_LOCK` is rejected at admission. Docker has no
admission controller, so the Compose stack keeps mlock.

HashiCorp recommends disabling mlock for integrated (Raft) storage anyway: the
BoltDB file is mmap'd, so the pages mlock would pin are on disk regardless. The
guarantee you give up is "decrypted secrets are never swapped out" — close that
at the node, where Kubernetes already wants it closed: the kubelet refuses to
start with swap enabled unless explicitly told otherwise.

**Upgrading from an earlier revision of these manifests**, which used the `file`
backend at `/vault/file`: the storage backend and the mount path have both
changed, so the existing PVC is not readable by Raft. Migrate with
`vault operator migrate` before applying — see `docs/deployment/vault.md` §5.

**Upgrading across the label fix (K8S-F11):** the StatefulSet's `spec.selector`
gained a `component: vault` label, and a selector is immutable. `kubectl apply`
against a StatefulSet created from an earlier revision fails; recreate it
without touching the data:

```bash
kubectl -n axiam delete statefulset vault --cascade=orphan
kubectl apply -k k8s/
```

The PVC and the running pod both survive `--cascade=orphan`, and the new
StatefulSet adopts the pod once its labels match.

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
