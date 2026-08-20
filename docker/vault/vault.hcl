# Vault configuration for the production-shaped Compose stack.
#
# Close enough to production to exercise what differs from `-dev` mode —
# sealing, unsealing, persistent storage, TLS — and explicitly not a production
# Vault. See docs/deployment/vault.md and k8s/vault/ for the real thing.

ui = false

storage "file" {
  path = "/vault/file"
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

api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"

# Auto-unseal is deliberately absent here and deliberately present, commented,
# in k8s/vault/statefulset.yml. This stack is brought up by hand for testing, so
# a manual unseal is acceptable; a real deployment restarting into a sealed
# Vault at 3am is not.
