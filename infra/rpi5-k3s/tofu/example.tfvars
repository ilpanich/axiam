# Copy to `<stage>.auto.tfvars` in each stage directory, or pass with
# `run.sh <stage> <command> -var-file=...`. `*.auto.tfvars` is gitignored.
#
#     cp example.tfvars 10-platform/10-platform.auto.tfvars
#     cp example.tfvars 20-axiam/20-axiam.auto.tfvars
#     cp example.tfvars 30-vault-config/30-vault-config.auto.tfvars
#
# Unknown variables in an auto.tfvars file are an ERROR, not a warning, so each
# stage's copy has to be trimmed to the variables that stage declares. The
# sections below say which is which.
#
# NO SECRETS HERE, EVER. Every value in a tfvars file ends up in the state:
# the Vault root token goes in the ENVIRONMENT for one command
# (`read -rs VAULT_TOKEN && export VAULT_TOKEN`), the state encryption
# passphrase goes in TOFU_ENCRYPTION_PASSPHRASE, and neither is a variable.
#
# The hostname below is the one used throughout
# claude_dev/rpi5-prod-google-federation-guide.md, so the diff from this file to
# yours is small. Changing it means changing it in
# infra/rpi5-k3s/overlay/ingress-host.yml and overlay/configmap-env.yml too —
# those are manifests, not variables, and they are the source of truth for the
# five places the hostname appears in AXIAM's own configuration.

# --- every stage ----------------------------------------------------------
kubeconfig_path = "~/.kube/config"

# --- 10-platform only -----------------------------------------------------
# REQUIRED. Let's Encrypt registers the ACME account to this and sends expiry
# warnings to it. An address nobody reads is the reason most expired-certificate
# incidents are found by a user.
acme_email = "you@example.com"

# Keep these in step with infra/rpi5-k3s/scripts/versions.env.
ingress_nginx_chart_version = "4.15.1"
cert_manager_version        = "v1.21.2"

# --- 20-axiam and 30-vault-config -----------------------------------------
namespace = "axiam"

# --- 20-axiam only --------------------------------------------------------
# Honoured only on the FIRST boot of an empty volume. After that, changing one
# does not rotate anything — it breaks authentication. See credentials.tf.
db_username       = "axiam"
rabbitmq_username = "axiam"
amqp_vhost        = "axiam"

# gRPC on the public internet. OFF. Read docs/deployment/rpi5-k3s.md §14 before
# changing it: setting it publishes three services on 443 through the ingress,
# turns on the gRPC listener's TLS from the same leaf the REST listener uses,
# and sets AXIAM__GRPC__STRICT_REVOCATION. Never publish gRPC as a NodePort.
grpc_public = false

# --- 30-vault-config only -------------------------------------------------
# Must match AXIAM__AUTH__VAULT_MOUNT / _PATH in k8s/server/configmap.yml.
vault_mount = "secret"
vault_path  = "axiam"
policy_name = "axiam"

# 32 days, mirroring the Compose path's `-period=768h`. A PERIODIC token: it
# renews indefinitely while it is used, rather than expiring at a moment nobody
# chose.
server_token_period_hours = 768

# `repo_root` and `vault_ca_cert_path` are supplied by run.sh — the first is
# where it found this repository, the second is a 0600 temp file it extracts the
# Vault CA into for the length of one command. Do not set them here.
