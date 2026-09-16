# Stage 30 — Vault's mount, AXIAM's policy, the server's token, and seeding.
#
# Runs AFTER the human ceremony (scripts/02-vault-ceremony.sh), because the
# Vault provider needs an initialised, unsealed Vault and a token to configure
# it with — neither of which exists until a person has been handed five shares.
# That ordering is the whole reason this tree is staged.
#
# WHAT IS DELIBERATELY NOT HERE: the secrets themselves. `vault_kv_secret_v2`
# would put the OPAQUE setup key in the state file. Seeding goes through the
# repository's own `scripts/vault-seed.sh`, which is idempotent, waits for an
# ACTIVE node rather than a merely-listening one, refuses to write into a Vault
# it cannot read, and pins its write with KV v2's `cas`. Those are properties a
# provider resource does not have, and the Pi guide §16 records that they were
# earned the hard way: a seeder that treats a refused read as an empty Vault
# rotates every key under a live datastore, and the only symptom is every login
# answering `Cryptography error: AES-GCM decrypt: aead::Error`.
terraform {
  required_version = ">= 1.6"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "4.5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.35.1"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "vault" {
  # Reached through a port-forward that run.sh opens, NOT through the ingress:
  # Vault is a ClusterIP service and is never published. The address is
  # 127.0.0.1 and the listener certificate carries it as an IP SAN, so this
  # verifies properly — `skip_tls_verify` is not set here and must not be.
  address      = "https://127.0.0.1:${var.vault_port_forward}"
  ca_cert_file = var.vault_ca_cert_path

  # Read from VAULT_TOKEN in the environment. NOT a variable: a variable can be
  # set in a .tfvars file, and every value in a .tfvars file ends up in the
  # state. A root token does not go in a state file even an encrypted one.
  #
  # run.sh checks VAULT_TOKEN is set before it starts, and tells you to use
  # `read -rs` so it does not land in ~/.bash_history either.

  # A short-lived child token for this run rather than using the root token
  # directly for every call. It is revoked when the provider finishes, so an
  # interrupted apply leaves at most one 20-minute credential behind instead of
  # a root session.
  max_lease_ttl_seconds = 1200
}
