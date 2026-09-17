# The token is NOT an output. It is in the state — which is why the state is a
# secret — but an output would additionally put it on your terminal, in
# scrollback, and in any log of this run. Read it back deliberately if you need
# it:
#   kubectl -n axiam get secret axiam-vault-token \
#     -o jsonpath='{.data.AXIAM__AUTH__VAULT_TOKEN}' | base64 -d

output "policy_name" {
  description = "Written from docker/vault/axiam-policy.hcl — the same file the Compose path uses."
  value       = vault_policy.axiam.name
}

output "kv_mount" {
  value = "${vault_mount.kv.path}/${var.vault_path}"
}

output "server_token_accessor" {
  description = "The ACCESSOR, not the token. Enough to look it up or revoke it; not enough to use it."
  value       = vault_token.axiam_server.token_accessor_id
}

output "next_step" {
  value = <<-EOT
    1. REVOKE THE ROOT TOKEN. It has done its job and it is the one credential
       that can undo everything above:

         kubectl -n ${var.namespace} exec vault-0 -- \
           env VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/vault/tls/ca.crt \
               VAULT_TOKEN="$VAULT_TOKEN" vault token revoke -self
         unset VAULT_TOKEN

    2. Prove the server's token is scoped, rather than assuming it:

         VAULT_TOKEN="$(kubectl -n ${var.namespace} get secret axiam-vault-token \
           -o jsonpath='{.data.AXIAM__AUTH__VAULT_TOKEN}' | base64 -d)" \
           infra/rpi5-k3s/scripts/05-verify.sh

       It must say `ok`, not `OVER-SCOPED`. Nothing inside AXIAM can tell a
       scoped token from a root one — both read the secret successfully — so
       this check is the only thing that can.

    3. AXIAM's own first run:

         read -rs AXIAM_ADMIN_PASSWORD && export AXIAM_ADMIN_PASSWORD
         infra/rpi5-k3s/scripts/03-axiam-bootstrap.sh
  EOT
}
