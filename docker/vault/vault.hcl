# Vault configuration for the production-shaped Compose stack.
#
# What this is, honestly: a Vault close enough to production to exercise what
# differs from `-dev` mode — sealing, unsealing, persistent storage, TLS, a
# scoped token — and NOT a production Vault, for exactly one reason that is
# named below and nowhere hidden. See docs/deployment/vault.md §5 and
# claude_dev/rpi5-prod-google-federation-guide.md for the real ceremony.

ui = false

# Raft (integrated storage) rather than the `file` backend.
#
# Three reasons, none of them cosmetic:
#
#  1. It is what HashiCorp supports and documents. `file` is a single-node
#     development backend; every operational procedure worth having — snapshot,
#     restore, autopilot, adding a second node — is written for Raft.
#  2. It has a backup story. `vault operator raft snapshot save` produces a
#     consistent point-in-time copy while Vault is running. Backing up `file`
#     means copying a directory underneath a live process and hoping.
#  3. A single-node Raft cluster is a supported configuration, and growing it to
#     three later is `retry_join` plus a restart — it does not require
#     re-seeding, which would mean a password reset for every user in every
#     tenant because the OPAQUE setup key would change.
#
# MIGRATING AN EXISTING STACK: this uses a NEW volume (`vault-raft-data`), so a
# stack that was already running `file` storage is left completely intact at its
# old mount and nothing is destroyed. To carry the data across, snapshot the old
# Vault or re-seed a fresh one; `docs/deployment/vault.md` §5 has the procedure.
# A stack that has never been initialised just works.
storage "raft" {
  path    = "/vault/data"
  node_id = "axiam-vault-0"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/vault/tls/server.pem"
  tls_key_file  = "/vault/tls/server-key.pem"
  # TLS is not optional. The token AXIAM presents on every fetch is a bearer
  # credential for the OPAQUE setup key; over plaintext, anything on the Docker
  # network can take it.
  tls_min_version = "tls12"
}

# Raft needs to know how to reach itself; unlike the `file` backend these are
# load-bearing rather than advisory, and a mismatch shows up as a node that
# never finishes joining its own cluster.
api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"
disable_mlock = false

# ---------------------------------------------------------------------------
# THE ONE THING THAT MAKES THIS NOT PRODUCTION: auto-unseal
# ---------------------------------------------------------------------------
#
# There is no `seal` block here, so this Vault uses Shamir and comes back SEALED
# after every restart. `just prod-up` unseals it from a key it wrote to
# docker/.secrets/vault-init.json — which is to say, from a key sitting on the
# same disk as the sealed data. That is not Shamir's scheme with the shares
# stored badly; it is no seal at all, and it is acceptable here only because
# this stack is brought up by hand on a laptop with a human watching.
#
# A real deployment configures one of these BEFORE it goes live —
# docs/deployment/vault.md §5.3 explains why this is the step most often
# deferred and most expensive to defer. Uncomment ONE and run
# `vault operator unseal -migrate` once:
#
#   seal "gcpckms" {          # cheapest; ~$0.06/key/month
#     project    = "my-project"
#     region     = "global"
#     key_ring   = "vault"
#     crypto_key = "unseal"
#   }
#
#   seal "awskms" {           # ~$1/key/month
#     region     = "eu-west-1"
#     kms_key_id = "arn:aws:kms:eu-west-1:123456789012:key/abcd-..."
#   }
#
#   seal "azurekeyvault" {
#     vault_name = "my-vault"
#     key_name   = "unseal"
#   }
#
#   seal "transit" {          # only if the OTHER Vault lives somewhere else
#     address    = "https://vault.elsewhere:8200"
#     key_name   = "autounseal"
#     mount_path = "transit/"
#   }
#
# `seal "pkcs11"` (HSM, and any TPM the host happens to have) is Vault
# **Enterprise** only and is not an option on the open-source binary this stack
# runs, whatever the hardware.
