# ---------------------------------------------------------------------------
# 1. The KV v2 mount
# ---------------------------------------------------------------------------
#
# `vault-seed.sh` would enable this itself if it found it missing, and doing it
# here as well is not redundant: this stage's other resources depend on the
# mount existing, and a dependency expressed in the graph is one OpenTofu can
# order. The seeder's own check then finds it present and does nothing.
resource "vault_mount" "kv" {
  path = var.vault_mount
  type = "kv"
  options = {
    version = "2"
  }
  description = "AXIAM deployment secrets and CA signing keys"

  lifecycle {
    # Destroying a KV v2 mount destroys every version of every secret in it,
    # including `opaque_setup_key` — which means a password reset for every user
    # in every tenant. There is no recovery from this that does not involve
    # telling your users.
    prevent_destroy = true
  }
}

# ---------------------------------------------------------------------------
# 2. AXIAM's policy — read from the repository, not restated here
# ---------------------------------------------------------------------------
#
# `file()` on docker/vault/axiam-policy.hcl, which is the SAME file
# `scripts/vault-policy.sh` writes and the same one `just prod-up` uses on the
# Compose path. One source of truth, so the Kubernetes deployment and the
# documented Compose ceremony cannot drift from each other or from what the
# server actually needs.
#
# The shape is "read-only on the deployment secrets, plus writes confined to the
# CA-key prefix". Both halves are load-bearing. A token with only the first half
# boots fine, serves every request, and then answers the first CA generation
# with a 403 on write — because CA key custody inherits AXIAM__AUTH__VAULT_ADDR
# and _TOKEN when no AXIAM__PKI__VAULT_* pair is set, which is the intended
# single-Vault arrangement and what the overlay configures.
#
# Policies are evaluated PER REQUEST, not baked into a token at issue time, so
# re-applying this repairs an already-running server's token in place: no
# restart, no re-issue, no re-seed.
resource "vault_policy" "axiam" {
  name   = var.policy_name
  policy = file("${var.repo_root}/docker/vault/axiam-policy.hcl")
}

# ---------------------------------------------------------------------------
# 3. Seed — through the repository's own script
# ---------------------------------------------------------------------------
#
# NOT `vault_kv_secret_v2`. That resource would put every value — the OPAQUE
# setup key, the auth pepper, the JWT signing key — in the state file, and it
# would overwrite on drift, which for `opaque_setup_key` means every OPAQUE
# registration record in every tenant becomes unopenable.
#
# `vault-seed.sh` mints only what is MISSING, and the guarantee rests on a read
# it refuses to guess at: it waits for an ACTIVE node (a 200 on sys/health, not
# a 429 standby or a 503 sealed), hands the read's HTTP STATUS to its payload
# builder rather than the body alone, and writes with KV v2's `cas` pinned to
# the version it read.
#
# It also mints the Ed25519 JWT keypair itself, with openssl, without the key
# ever touching disk — which is why this stage does NOT generate one with
# `tls_private_key` and pass it in. A pre-generated keypair would exist in the
# OpenTofu state for no benefit; minted here it exists only in Vault.
#
# `triggers_replace` on the policy means a policy change re-runs the seeder,
# which is harmless (it preserves everything present) and catches the case where
# the seeding token gained a capability it previously lacked.
resource "terraform_data" "seed" {
  depends_on = [vault_mount.kv, vault_policy.axiam]

  triggers_replace = {
    policy = vault_policy.axiam.policy
    mount  = "${var.vault_mount}/${var.vault_path}"
  }

  provisioner "local-exec" {
    # VAULT_TOKEN is inherited from the environment run.sh checked — it is not
    # a variable and so is not in the state. VAULT_CACERT makes the seeder
    # verify the listener; it has a VAULT_SKIP_VERIFY escape hatch for the
    # self-signed Compose stack and it is deliberately not used here.
    command = "bash '${var.repo_root}/scripts/vault-seed.sh'"

    environment = {
      VAULT_ADDR   = "https://127.0.0.1:${var.vault_port_forward}"
      VAULT_CACERT = var.vault_ca_cert_path
      VAULT_MOUNT  = var.vault_mount
      VAULT_PATH   = var.vault_path
    }
  }
}

# ---------------------------------------------------------------------------
# 4. The server's token
# ---------------------------------------------------------------------------
resource "vault_token" "axiam_server" {
  depends_on = [terraform_data.seed]

  policies = [vault_policy.axiam.name]

  # PERIODIC, not fixed-expiry. A periodic token renews indefinitely as long as
  # it is used within each period; a fixed-TTL token would take the deployment
  # down at its expiry, at a moment nobody chose.
  period = "${var.server_token_period_hours}h"

  renewable       = true
  renew_min_lease = 3600
  renew_increment = var.server_token_period_hours * 3600
  display_name    = "axiam-server"
  no_parent       = true

  # THIS TOKEN IS IN THE STATE FILE. It is one of the two reasons the state is a
  # secret (the other is the datastore password in stage 20). Encrypt the state
  # — encryption.tofu — and back it up somewhere that is not this Pi.
  #
  # `no_parent` so revoking whatever token created it does not cascade and
  # revoke this one. The ceremony's very next step is revoking the root token,
  # and without this that revocation would take the server's credential with it.

  lifecycle {
    # Re-creating this on every apply would hand the server a new token while
    # the old one is still in its environment, and the failure — a 403 on the
    # first secret fetch after the next restart — arrives hours later.
    ignore_changes = [period, policies]
  }
}

# A separate Secret from stage 20's `axiam-secrets`, on purpose: one object with
# two owners across two stages is how a token gets blanked by a re-apply of the
# stage that does not have it. The overlay gives the server a second `envFrom`
# for this one.
resource "kubernetes_secret" "vault_token" {
  metadata {
    name      = "axiam-vault-token"
    namespace = var.namespace
    labels    = { app = "axiam", component = "server" }
  }
  data = {
    AXIAM__AUTH__VAULT_TOKEN = vault_token.axiam_server.client_token
  }
}

# The server pod has been in CreateContainerConfigError since stage 20, waiting
# for the Secret above. The kubelet retries with backoff and would get there on
# its own, eventually; this makes "eventually" now.
resource "terraform_data" "restart_server" {
  depends_on = [kubernetes_secret.vault_token]

  triggers_replace = {
    token_accessor = vault_token.axiam_server.id
  }

  provisioner "local-exec" {
    command = <<-EOT
      kubectl --kubeconfig='${var.kubeconfig_path}' -n '${var.namespace}' \
        rollout restart deployment/axiam-server
    EOT
  }
}
