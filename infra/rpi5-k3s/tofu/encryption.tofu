# State encryption — OpenTofu only, and ignored by Terraform BY DESIGN.
#
# Terraform does not read `.tofu` files at all, so this tree validates under
# both binaries while using the one OpenTofu-only feature that matters here.
# Nothing else in `tofu/` uses OpenTofu-only syntax.
#
# ###########################################################################
# WHY THE STATE IS A SECRET
# ###########################################################################
#
# Stage 20's state holds the SurrealDB root password and the RabbitMQ password
# (inside the AMQP URL). Stage 30's holds the server's Vault token — which is a
# bearer credential for a Vault containing the OPAQUE setup key, the auth pepper
# and the JWT signing key. OpenTofu writes all of that in cleartext unless this
# block is configured.
#
# The passphrase is held like an unseal share: OFF THE PI. If it is in a file
# next to the state, you have encrypted the state against someone who steals the
# backup and nobody else — which is a real threat model, but say out loud that
# it is the one you chose.
#
# ###########################################################################
# TO TURN IT ON
# ###########################################################################
#
# 1. SYMLINK THIS FILE INTO EACH STAGE — OpenTofu reads configuration per root
#    module, so a file one directory up is not in scope:
#
#      for s in 10-platform 20-axiam 30-vault-config; do
#        ln -sf ../encryption.tofu "infra/rpi5-k3s/tofu/$s/encryption.tofu"
#      done
#
# 2. Uncomment the block below.
#
# 3. Export the passphrase for every run. run.sh refuses to continue if an
#    encrypted state exists and this is unset, rather than silently writing a
#    second, unencrypted state file:
#
#      read -rs TF_VAR_state_passphrase   # not used as a variable; see below
#      export TOFU_ENCRYPTION_PASSPHRASE="$TF_VAR_state_passphrase"
#
# 4. MIGRATE AN EXISTING PLAINTEXT STATE rather than assuming it converts:
#    set `enforced = false` on the first apply so OpenTofu can read the old
#    state and write an encrypted one, then set it back to `true`. Turning it on
#    with `enforced = true` against a plaintext state fails to decrypt something
#    that was never encrypted, and the error does not say that.
#
# 5. BACK IT UP BEFORE STEP 4. An encrypted state whose passphrase is lost is
#    a state you no longer have, and stage 20 will not re-mint credentials that
#    a live datastore has already recorded.
#
# terraform {
#   encryption {
#     key_provider "pbkdf2" "passphrase" {
#       # Read from TOFU_ENCRYPTION_PASSPHRASE in the environment. NOT a
#       # variable: a variable is settable from a .tfvars file, and a tfvars
#       # file holding the key to the state defeats encrypting the state.
#       passphrase = env("TOFU_ENCRYPTION_PASSPHRASE")
#     }
#
#     method "aes_gcm" "default" {
#       keys = key_provider.pbkdf2.passphrase
#     }
#
#     state {
#       method = method.aes_gcm.default
#       # `true` refuses to write an unencrypted state at all. Set it to false
#       # for ONE apply when migrating an existing plaintext state (step 4).
#       enforced = true
#     }
#
#     # The plan file too: a saved plan contains the same values as the state it
#     # would produce. run.sh writes one for every apply, so this is not
#     # hypothetical.
#     plan {
#       method   = method.aes_gcm.default
#       enforced = true
#     }
#   }
# }
