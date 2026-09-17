output "ingress_nginx_namespace" {
  description = "Confirms the namespace the two NetworkPolicies select by name."
  value       = helm_release.ingress_nginx.namespace
}

output "cert_manager_version" {
  value = helm_release.cert_manager.version
}

output "acme_issuers" {
  description = "Both are created; stage 20's acme_issuer variable picks one. Start with staging."
  value       = sort(keys(kubectl_manifest.acme_issuers))
}

output "private_ca_issuer" {
  description = "The ClusterIssuer every internal leg's leaf is issued from."
  value       = "axiam-ca"
}
