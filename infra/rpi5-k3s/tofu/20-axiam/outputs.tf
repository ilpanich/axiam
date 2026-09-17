# Nothing here is a secret. The credentials are in the STATE, which is the thing
# to protect (see encryption.tofu and §6 of the operator guide); an output would
# also put them on the terminal, in scrollback and in any CI log that ran this.
#
# Read a value back deliberately when you need it, one at a time:
#   kubectl -n axiam get secret surrealdb-credentials \
#     -o jsonpath='{.data.password}' | base64 -d

output "namespace" {
  value = var.namespace
}

output "applied_object_count" {
  description = "Objects the overlay rendered and this stage applied."
  value = (
    length(data.kustomization_overlay.axiam.ids_prio[0]) +
    length(data.kustomization_overlay.axiam.ids_prio[1]) +
    length(data.kustomization_overlay.axiam.ids_prio[2])
  )
}

output "grpc_public" {
  description = "Whether the gRPC surface is published on 443 through the ingress."
  value       = var.grpc_public
}

output "next_step" {
  value = <<-EOT
    The server pod will sit in CreateContainerConfigError until stage 30 creates
    the `axiam-vault-token` Secret. That is expected — it cannot serve a login
    before Vault is initialised and seeded.

      infra/rpi5-k3s/scripts/02-vault-ceremony.sh
      read -rs VAULT_TOKEN && export VAULT_TOKEN
      infra/rpi5-k3s/run.sh 30-vault-config apply
      unset VAULT_TOKEN
  EOT
}
