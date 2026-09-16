variable "kubeconfig_path" {
  description = "Path to the kubeconfig for the k3s cluster. 01-install-k3s.sh writes one to ~/.kube/config, mode 600."
  type        = string
  default     = "~/.kube/config"
}

variable "acme_email" {
  description = <<-EOT
    The address Let's Encrypt registers the ACME account to, and sends expiry
    warnings to. An account registered with an address nobody reads is the
    reason most expired-certificate incidents are found by a user.
  EOT
  type        = string

  validation {
    condition     = can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.acme_email))
    error_message = "acme_email must be a real address you read."
  }
}

variable "ingress_nginx_chart_version" {
  description = "ingress-nginx Helm chart version. Keep it in step with infra/rpi5-k3s/scripts/versions.env."
  type        = string
  default     = "4.15.1"
}

variable "cert_manager_version" {
  description = "cert-manager chart and app version (the same string). Keep it in step with versions.env."
  type        = string
  default     = "v1.21.2"
}

variable "private_ca_duration_hours" {
  description = <<-EOT
    Lifetime of the in-cluster root CA. Ten years by default, renewed at nine:
    a private root that expires takes every internal leg down at once, and
    rotating it is a coordinated restart of Vault, RabbitMQ, the ingress and the
    server. That is an event to schedule, not one to meet.
  EOT
  type        = number
  default     = 87600
}
