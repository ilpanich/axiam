variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}

variable "namespace" {
  type    = string
  default = "axiam"
}

variable "vault_port_forward" {
  description = "Local port run.sh forwards Vault's 8200 to. Vault is ClusterIP and is never published."
  type        = number
  default     = 18200
}

variable "vault_ca_cert_path" {
  description = <<-EOT
    The CA bundle that verifies Vault's listener. run.sh extracts `ca.crt` from
    the `vault-tls` Secret into a 0600 temp file and passes the path here.
    There is no verification-skip option in this stage, and there must not be:
    the token every call carries is a bearer credential for a Vault that holds
    the OPAQUE setup key.
  EOT
  type        = string
}

variable "vault_mount" {
  description = "KV v2 mount point. Must match AXIAM__AUTH__VAULT_MOUNT in k8s/server/configmap.yml."
  type        = string
  default     = "secret"
}

variable "vault_path" {
  description = "Path within the mount. Must match AXIAM__AUTH__VAULT_PATH."
  type        = string
  default     = "axiam"
}

variable "policy_name" {
  description = "Must match what the server's token is issued against. `just vault-status` expects `axiam`."
  type        = string
  default     = "axiam"
}

variable "server_token_period_hours" {
  description = <<-EOT
    A PERIODIC token, renewed indefinitely as long as it is used within each
    period — not a token with a fixed expiry, which would take the deployment
    down 768 hours after it was issued, at a moment nobody chose.

    768h (32 days) mirrors the Compose path's `-period=768h` exactly, which is
    what `docs/deployment/vault.md` documents and what the Pi guide §7.3 does.
  EOT
  type        = number
  default     = 768
}

variable "repo_root" {
  description = "Repository root, so this stage can run scripts/vault-seed.sh and read docker/vault/axiam-policy.hcl rather than restating either."
  type        = string
}
