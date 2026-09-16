variable "kubeconfig_path" {
  type    = string
  default = "~/.kube/config"
}

variable "namespace" {
  description = "Must match k8s/namespace.yml and the overlay. Changing it is not a one-variable change."
  type        = string
  default     = "axiam"
}

variable "overlay_path" {
  description = "The kustomize overlay to render, relative to this directory."
  type        = string
  default     = "../../overlay"
}

variable "grpc_public" {
  description = <<-EOT
    Publish the gRPC surface on 443, THROUGH the ingress. Off by default
    (invariant 4).

    Setting it does three things together, which is the point of it being one
    variable: adds overlay/ingress-grpc.yml to the render, sets the two flat
    AXIAM__GRPC_TLS_*_PATH variables to the SAME leaf the REST listener serves,
    and sets AXIAM__GRPC__STRICT_REVOCATION=true. Miss any one and you get a
    listener in cleartext, a second certificate to renew, or a session that
    stays valid over gRPC for fifteen minutes after logout.

    Read docs/deployment/rpi5-k3s.md §14 before setting it. NEVER publish gRPC
    as a NodePort at 50051: nothing then writes X-Forwarded-For, and a client
    picks its own rate-limit bucket per call. No TRUSTED_HOPS value fixes that.
  EOT
  type        = bool
  default     = false
}

variable "amqp_vhost" {
  description = "Must match RABBITMQ_DEFAULT_VHOST in k8s/rabbitmq/statefulset.yml. Honoured only on the broker's first boot."
  type        = string
  default     = "axiam"
}

variable "db_username" {
  description = "SurrealDB root username. Honoured only on the FIRST boot of an empty volume."
  type        = string
  default     = "axiam"
}

variable "rabbitmq_username" {
  description = "RabbitMQ user. Honoured only on the FIRST boot of an empty volume."
  type        = string
  default     = "axiam"
}

variable "internal_leaf_duration_hours" {
  description = "Lifetime of the server's and the ingress client's leaves. Ninety days: both consumers reload without a restart."
  type        = number
  default     = 2160
}

variable "restart_required_leaf_duration_hours" {
  description = <<-EOT
    Lifetime of the Vault and RabbitMQ leaves. One year, not ninety days, and
    deliberately: neither process reloads its TLS files, so renewal there is a
    pod restart — and a Vault restart without auto-unseal is a human with three
    shares. Make it a scheduled annual event rather than a quarterly surprise.
  EOT
  type        = number
  default     = 8760
}
