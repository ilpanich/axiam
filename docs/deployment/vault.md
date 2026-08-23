# Secrets and HashiCorp Vault

AXIAM holds ten long-lived secrets. Two of them — the JWT signing key and the
OPAQUE setup key — are the difference between "an attacker read your database"
and "an attacker owns your identity provider".

This document covers where they come from, how to run Vault for them, what has
to be done by hand, and what to use instead if you are not a Vault shop.

---

## 1. What AXIAM needs, and what it does not care about

AXIAM's requirement is small and worth stating before any of the setup below,
because most of that setup is convenience:

> A KV v2 secret at `<mount>/<path>` whose fields are named after the constants
> in `crates/axiam-core/src/secrets.rs`.

That is all. AXIAM does not care who runs Vault, whether it is HA, or how it is
unsealed. If your organisation already runs Vault, point
`AXIAM__AUTH__VAULT_ADDR` at it, create the policy in §5, and skip everything
else here.

### The secrets

| Field | Shape | What losing it costs |
|---|---|---|
| `opaque_setup_key` | 32-byte hex | **A password reset for every user in every tenant.** It encrypts each tenant's OPRF seed; without it no OPAQUE record can be opened. |
| `jwt_private_key_pem` | Ed25519 PEM | **Total compromise.** Whoever holds it can mint a token for any principal in any tenant. |
| `pki_encryption_key` | 32-byte hex | **CA compromise.** It encrypts CA private keys at rest *under database custody*; a leak lets an attacker issue certificates every mTLS client trusts. CAs whose keys are in Vault do not depend on it — see [CA key custody](../pki/README.md#ca-key-custody). Still needed to open any CA created before you switched. |
| `auth_pepper` | text | Every stored password hash is invalidated if it *changes*; a leak makes offline attack on stolen hashes cheaper. |
| `opaque_session_key` | 32-byte hex | In-flight OPAQUE exchanges (120 s) are invalidated. Cheap to rotate — deliberately separate from the setup key for exactly this reason. |
| `mfa_encryption_key` | 32-byte hex | Stored TOTP secrets become undecryptable. |
| `federation_encryption_key` | 32-byte hex | Stored IdP client secrets become undecryptable. |
| `email_encryption_key` | 32-byte hex | Stored email addresses become undecryptable. |
| `gdpr_pseudonym_pepper` | 32-byte hex | Existing audit pseudonyms stop linking to new ones; the audit trail breaks. |
| `amqp_signing_key` | 32-byte hex | AMQP message signing is mandatory and has no unsigned path, so a release build **refuses to start** without it. Rotating it needs producers and consumers moved together. |
| `jwt_public_key_pem` | Ed25519 PEM | Not secret, but a mismatched pair is a confusing outage. |

`just vault-status` prints which of these your Vault holds — presence only,
never values.

### Seeding them

`just vault-seed` mints every one of the above that is missing and leaves every
one that is present alone. It targets whatever Vault you point it at:

```sh
export VAULT_ADDR=https://vault.internal:8200
export VAULT_TOKEN=<a token with create/update on the KV path>
export VAULT_CACERT=/etc/ssl/certs/your-ca.pem   # recommended
just vault-seed
```

Everything is generated from a CSPRNG — `secrets.token_hex(32)` for the keys,
`secrets.token_urlsafe(48)` for the pepper, and `openssl genpkey -algorithm
ed25519` for the signing keypair, which is piped between processes and **never
written to disk**.

The idempotence is not politeness. Re-running the seeder is something you will
do — after adding a key, after a restore, by accident — and regenerating
`opaque_setup_key` costs a password reset for every user in every tenant while
regenerating `jwt_private_key_pem` invalidates every token in flight. An
existing value is always preserved. The one deliberate exception is a keypair
you supply explicitly through `JWT_PRIVATE_KEY_PEM` / `JWT_PUBLIC_KEY_PEM`,
which is how `just prod-up` moves the pair it generated on disk into Vault.

**X.509 material is not seeded here, and that is deliberate.** The broker's
AMQPS certificate reaches the server as a *file path*
(`AXIAM__AMQP__TLS__CA_CERT_PATH`), mounted into a container that cannot read
Vault; and Vault cannot hold the certificate that fronts Vault. `just tls-certs`
generates both, idempotently.

Organization **CA signing keys** are a third case, and they *can* live in Vault
— but not seeded here, because there is nothing to seed. They are created at
runtime, one per CA, and AXIAM writes them itself under a prefix you configure.
Nothing about them is known at deployment time, so the seeder has no work to do.
See [CA key custody](../pki/README.md#ca-key-custody) for how to turn it on and
what policy the token needs. The certificates themselves stay in the database:
they are public, and a second copy in Vault would be a second source of truth
for something the database already owns.

---

## 2. Choosing a provider

`AXIAM__AUTH__SECRET_PROVIDER` selects one. An unknown value is **refused at
startup** rather than falling back, because a typo silently reverting to `env`
presents as "OPAQUE stopped working" with nothing in the logs explaining why.

| Value | Use it when | Honest assessment |
|---|---|---|
| `env` (default) | Development, and any deployment not yet ready to run a KMS. | Simple and universal. Puts the setup key in your pod spec, your Compose file, your CI variables and `/proc/<pid>/environ`. |
| `file` | Your platform mounts secrets as files: Docker secrets, Kubernetes `Secret` volumes, Vault Agent Injector, External Secrets, the AWS/GCP CSI drivers. | **Not a security improvement over `env`** — same trust boundary. It exists because it is the shape those tools produce. |
| `vault` | Production. | The key never enters a container spec, a Compose file, a CI variable or a shell history. Access is authenticated per workload, audited, and revocable *after the fact*. Rotation is a write rather than a redeploy. |

### What none of them do

The key must reach the AXIAM process to decrypt anything, so **none of these
defends against a compromised application server.** Vault defends against the
ways keys actually leak — a config file in git, an over-shared CI variable, a
`kubectl describe pod`, a backup of an orchestrator's etcd — not against an
attacker with code execution on the server.

The construction that *would* is envelope encryption against a Transit-style
API where the plaintext key never leaves the KMS, at the cost of a network round
trip per seal and open. AXIAM's `SecretProvider` trait is the place to add it,
and doing so requires no change to any authentication code.

### Why the seeds are in the database

A reasonable question, and the answer is that only the *ciphertext* is:
`opaque_server_setup` rows are AES-256-GCM, and the key comes from the provider
above. Moving the seeds to a file on the server volume would put them on the
same side of the trust boundary as the key, break replicas (a tenant created on
one would be unopenable on another), lose transactionality with the credential
rows, and turn a lost volume into total tenant lockout. See
[`claude_dev/opaque-design.md`](../../claude_dev/opaque-design.md) for the full
argument.

---

## 3. Local development

Vault is **optional** locally and off by default.

```bash
just dev-up      # SurrealDB + RabbitMQ. No Vault; provider stays `env`.
just vault-up    # Adds a dev-mode Vault and seeds every secret into it.
just vault-status
```

`just vault-up` prints the three exports that switch your local server over.

Dev-mode Vault is in-memory, starts unsealed, listens on plain HTTP and uses a
fixed root token. Every one of those is wrong for production — which is the
point: it removes the unseal ceremony from your edit-compile-run loop.

---

## 4. The Compose stack

Vault is **mandatory** here and `just prod-up` does the whole ceremony:
generates TLS material, starts Vault, initialises it, unseals it, seeds the
secrets, then starts the server.

```bash
just prod-up
```

Two things about this stack are deliberately not production:

1. **The unseal key and root token are written to
   `docker/.secrets/vault-init.json`.** That file is the whole of your Vault.
   It exists so a local stack survives `docker compose restart` without a
   human. Never do this on a real deployment.
2. **There is no auto-unseal**, so a restart leaves Vault sealed until
   `just prod-up` runs again.

---

## 5. Production: what you must do by hand

The manifests in `k8s/vault/` deploy a single-node Vault with file storage —
production-*shaped*, not production-*ready*. Most teams should run
[HashiCorp's Helm chart](https://github.com/hashicorp/vault-helm) with Raft and
3–5 replicas instead, or use an existing Vault. Either way, the steps below are
what AXIAM needs and none of them can be automated safely.

### 5.1 TLS

Vault's listener must be TLS. The token AXIAM presents on every fetch is a
bearer credential for the setup key; over plaintext, anything on the pod network
can take it.

Provide a certificate for `vault.axiam.svc.cluster.local` as a Secret named
`vault-tls` with `tls.crt` and `tls.key`. With cert-manager:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: vault-tls
  namespace: axiam
spec:
  secretName: vault-tls
  issuerRef: { name: your-issuer, kind: ClusterIssuer }
  dnsNames:
    - vault.axiam.svc.cluster.local
    - vault
```

Then tell AXIAM which CA to trust. `AXIAM__AUTH__VAULT_CA_CERT_PATH` points at a
PEM bundle mounted into the server; it is **additive**, so a Vault behind a
publicly-trusted certificate needs nothing and can leave it unset:

```yaml
env:
  - name: AXIAM__AUTH__VAULT_CA_CERT_PATH
    value: /etc/axiam/vault-tls/ca.pem
```

This is not optional detail for a private issuer. The server's HTTP client is
built on rustls with its trust anchors compiled in, so there is no
`SSL_CERT_FILE` or system trust store to drop a certificate into — an unnamed CA
fails at the handshake, and the startup panic reports only "error sending
request", which points at the network rather than at trust.

### 5.2 Initialise — once, and never again

```bash
kubectl exec -n axiam vault-0 -- vault operator init \
    -key-shares=5 -key-threshold=3 -format=json
```

**This output is printed once and cannot be recovered.** It contains five unseal
key shares and a root token.

- Give each share to a **different person**. Three of the five must cooperate to
  unseal, which is the entire point of Shamir's scheme — do not put all five in
  one password manager, and do not put them in the same place as the root token.
- The root token should be used for §5.3 and §5.4 and then **revoked**:
  `vault token revoke <root-token>`. Generate a new one with
  `vault operator generate-root` on the rare occasions you need it.

### 5.3 Configure auto-unseal — do this before you go live

Without it, every restart — a node drain, an upgrade, an OOM kill — leaves Vault
sealed and AXIAM unable to start, until three people are woken up. This is the
single most important production step and the one most often deferred.

Uncomment the appropriate `seal` block in `k8s/vault/statefulset.yml`:

```hcl
seal "awskms" {
  region     = "eu-west-1"
  kms_key_id = "arn:aws:kms:eu-west-1:123456789012:key/abcd-..."
}
```

Then migrate: `vault operator unseal -migrate` (three shares), once.

### 5.4 Enable KV v2 and create AXIAM's policy

```bash
vault secrets enable -path=secret -version=2 kv

vault policy write axiam - <<'EOF'
# Read-only, and scoped to exactly one path. A leaked AXIAM token must not be a
# key to the rest of your Vault.
path "secret/data/axiam" {
  capabilities = ["read"]
}
path "secret/metadata/axiam" {
  capabilities = ["read"]
}
EOF
```

### 5.5 Seed the secrets

```bash
export VAULT_ADDR=https://vault.example:8200
export VAULT_TOKEN=<a token with write on secret/data/axiam>
JWT_PRIVATE_KEY_PEM="$(cat jwt_ed25519.pem)" \
JWT_PUBLIC_KEY_PEM="$(cat jwt_ed25519.pub.pem)" \
    scripts/vault-seed.sh
```

The script **never regenerates a secret that already exists** — re-running it
after adding a key, or after a restore, is safe. That behaviour is unit-tested
(`scripts/test_vault_seed_payload.py`) precisely because getting it wrong would
mean a password reset for every user.

### 5.6 Authenticate AXIAM — prefer Kubernetes auth over a static token

A static token in `k8s/server/secret.yml` works and is what the manifests ship
with, because something must bootstrap the trust chain. It is not the best
answer: it does not rotate, and it sits in etcd.

With the Kubernetes auth method, the Secret disappears entirely and the pod
authenticates with its ServiceAccount token, which Kubernetes rotates:

```bash
vault auth enable kubernetes
vault write auth/kubernetes/config \
    kubernetes_host="https://$KUBERNETES_PORT_443_TCP_ADDR:443"

vault write auth/kubernetes/role/axiam \
    bound_service_account_names=axiam-server \
    bound_service_account_namespaces=axiam \
    policies=axiam \
    ttl=1h
```

AXIAM's provider takes a token rather than performing the login exchange itself,
so pair this with the [Vault Agent
Injector](https://developer.hashicorp.com/vault/docs/platform/k8s/injector),
which does the login and writes a rotating token to a shared volume. Then set
`AXIAM__AUTH__VAULT_TOKEN` from that file, or switch to
`AXIAM__AUTH__SECRET_PROVIDER=file` and let the injector template the secrets
directly.

> **Contributing:** native Kubernetes auth — AXIAM performing the login exchange
> itself and renewing its own lease — is a natural addition to
> `axiam_auth::secrets` and would remove the injector from this picture. It is
> not implemented today.

### 5.7 Verify before you rely on it

```bash
kubectl exec -n axiam deploy/axiam-server -- env | grep AXIAM__AUTH__VAULT
kubectl logs -n axiam deploy/axiam-server | grep 'secret provider ready'
```

The startup log names the provider that answered. That line exists because the
commonest OPAQUE misconfiguration is believing a key came from somewhere it did
not.

---

## 6. Rotation

Rotation cost differs enormously between these secrets, which is why AXIAM
splits them rather than using one key for everything.

| Secret | Cost | Procedure |
|---|---|---|
| `opaque_session_key` | Invalidates in-flight exchanges (≤120 s). | Write the new value, restart. Do it whenever you like. |
| `jwt_private_key_pem` | All existing access tokens become invalid. | Write, restart, accept one wave of re-authentication. Consider doing it during a maintenance window. |
| `auth_pepper` | **Invalidates every stored password hash.** | Effectively a password reset for everyone. Treat as an incident response measure, not maintenance. |
| `opaque_setup_key` | **Every OPAQUE record in every tenant becomes unopenable.** | Same. There is no re-encryption path, because the server cannot decrypt what it never had. |
| `mfa`/`federation`/`email`/`pki` keys | Existing ciphertext becomes undecryptable. | Requires re-encrypting the affected rows; no tooling ships for this today. |

The asymmetry is the reason `opaque_session_key` and `opaque_setup_key` are two
keys rather than one: sharing them would put the cheap rotation and the
catastrophic one on the same schedule, and an operator faced with that does
neither.

**Back up `opaque_setup_key` and `jwt_private_key_pem` separately from your
database backups.** A restore that brings back records without the key that
opens them is not a restore.

---

## 7. Not using Vault?

The provider is an interface, not a Vault dependency. The three below all work
today via `file` plus a CSI driver; each would also be a small, self-contained
implementation of `SecretProvider` if you prefer a direct integration.

### AWS Secrets Manager / KMS

```yaml
# Secrets Store CSI driver + AWS provider
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: { name: axiam-secrets, namespace: axiam }
spec:
  provider: aws
  parameters:
    objects: |
      - objectName: "axiam/opaque_setup_key"
        objectAlias: "opaque_setup_key"
      - objectName: "axiam/jwt_private_key_pem"
        objectAlias: "jwt_private_key_pem"
```

Mount it at `/run/secrets` and set:

```yaml
AXIAM__AUTH__SECRET_PROVIDER: "file"
AXIAM__AUTH__SECRET_DIR: "/run/secrets"
```

Use IRSA so the pod authenticates with its ServiceAccount rather than static
credentials.

### GCP Secret Manager

Same shape, with the GCP provider and Workload Identity:

```yaml
spec:
  provider: gcp
  parameters:
    secrets: |
      - resourceName: "projects/P/secrets/axiam-opaque-setup-key/versions/latest"
        path: "opaque_setup_key"
```

### Azure Key Vault

```yaml
spec:
  provider: azure
  parameters:
    usePodIdentity: "false"
    useVMManagedIdentity: "true"
    keyvaultName: "axiam-kv"
    objects: |
      array:
        - |
          objectName: opaque-setup-key
          objectAlias: opaque_setup_key
          objectType: secret
```

### PKCS#11 / an HSM

An HSM is the strongest option and the one that would genuinely survive a
compromised server, because the key never leaves the device. It needs the
envelope-encryption variant described in §2 rather than the `file` shortcut:
every seal and open becomes a call into the HSM. Implement `SecretProvider`
over your PKCS#11 library and select it in
`axiam_auth::secrets::SecretProviderKind::build`.

---

## 8. Troubleshooting

| Symptom | Cause |
|---|---|
| `secret provider configuration is invalid: AXIAM__AUTH__SECRET_PROVIDER=...` | Typo in the provider name. Valid values are `env`, `file`, `vault`. Refused rather than defaulted, on purpose. |
| `secret provider ... could not be initialised: vault: ... answered 403` | The token's policy does not grant `read` on `secret/data/axiam`. See §5.4. |
| `... answered 503` | Vault is sealed. See §5.3 — if this happened after a restart, you need auto-unseal. |
| OPAQUE endpoints return `503` | One or both OPAQUE keys are absent. `just vault-status`, or check the startup warning naming which half is missing. |
| `... must be 64 hex characters` | A secret in Vault is truncated or not hex. Caught at startup deliberately, rather than at the first login that needs it. |
| Startup succeeds but a key is silently absent | Check the `secret provider ready` log line names the provider you expect. `env` is the default and a typo in `AXIAM__AUTH__SECRET_PROVIDER` would have been refused — but an unset variable falls back to `env` quietly by design. |
